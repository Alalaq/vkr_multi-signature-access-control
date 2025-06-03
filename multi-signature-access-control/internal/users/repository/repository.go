package repository

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"multi-signature-access-control/internal/users/entities"
	"multi-signature-access-control/pkg/app_errors"
	"multi-signature-access-control/pkg/constants"
	"time"
)

type repositoryImpl struct {
	db *gorm.DB
}

type Repository interface {
	Detail(ctx context.Context, opts ...entities.UserDetailOpts) (entities.UserDetail, error)
	Create(ctx context.Context, request *entities.CreateUser) error
	GetAllUsers(ctx context.Context) ([]entities.UserDetail, error)
	GetAccessByUsername(ctx context.Context, username string, resource string) (constants.AccessLevel, error)
	GetNewRequestsByUsername(ctx context.Context, username string) ([]entities.PermissionReq, error)
	GetPermissionsByUsername(ctx context.Context, username string) ([]entities.PermissionReqResponse, error)
	DeclineRequest(ctx context.Context, id string) error
	AcceptRequest(ctx context.Context, id string, signature []byte) error
	GetHashedPublicKey(ctx context.Context, username string) (string, error)
	GetResponsiblesIDsByResource(ctx context.Context, resource string) ([]string, error)
	CreateRequests(ctx context.Context, username, resource string, responsiblesIDs []string) error
	CreateUser(ctx context.Context, user *entities.CreateUser) (entities.UserDetail, error)
	DeleteRequest(ctx context.Context, username string, resource string) error
	GetSignedRequests(ctx context.Context, requestID string) ([]entities.PermissionReqSignature, error)
	GetResource(ctx context.Context, requestID string) (string, error)
	GetRequiredSignatures(ctx context.Context, resource string) (int, error)
	StoreAggregatedApproval(ctx context.Context, requestID string, resource string, signature []byte) error
}

func NewUsersRepository(db *gorm.DB) Repository {
	return &repositoryImpl{db}
}

func (r *repositoryImpl) Detail(ctx context.Context, opts ...entities.UserDetailOpts) (entities.UserDetail, error) {
	args := new(entities.UserDetailRequest)
	for _, opt := range opts {
		opt(args)
	}

	query := r.db.WithContext(ctx).Table("users u").Select(`
		u.id,
		u.role_id,
		r.name AS role,
		u.username,
		u.email,
		u.hash_password,
		u.hash_public_key,
		u.created_at,
		u.updated_at`).
		Joins(`JOIN roles r ON r.id = u.role_id`)

	if args.ID != nil {
		query = query.Where("u.id = ?", args.ID)
	}

	if args.Email != nil {
		query = query.Where("u.email = ?", args.Email)
	}

	userDetail := entities.UserDetail{}

	if err := query.Take(&userDetail).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return userDetail, app_errors.NotFound(app_errors.ErrUserNotFound)
		}

		return userDetail, app_errors.InternalServerError(err)
	}

	return userDetail, nil
}

func (r *repositoryImpl) CreateUser(ctx context.Context, user *entities.CreateUser) (entities.UserDetail, error) {
	var userDetail entities.UserDetail

	query := `
		INSERT INTO users (id, role_id, username, email, hash_password, hash_public_key, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	err := r.db.WithContext(ctx).Exec(query,
		user.ID, user.RoleID, user.Username, user.Email, user.Password, user.PublicKey, time.Now()).Error
	if err != nil {
		return entities.UserDetail{}, err
	}

	err = r.db.WithContext(ctx).Raw(`
		SELECT id, role_id, username, email, hash_password, created_at, updated_at
		FROM users WHERE id = LAST_INSERT_ID()
	`).Scan(&userDetail).Error

	if err != nil {
		return entities.UserDetail{}, err
	}

	return userDetail, nil
}

func (r *repositoryImpl) Create(ctx context.Context, request *entities.CreateUser) error {
	return r.db.WithContext(ctx).Table("users").Create(request).Error
}

func (r *repositoryImpl) DeleteRequest(ctx context.Context, username string, resource string) error {
	result := r.db.WithContext(ctx).
		Table("permission_requests").
		Where("requester_id IN (SELECT id FROM users WHERE username = ?) AND resource = ?", username, resource).
		Delete(&struct{}{})

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil
		}
		return app_errors.InternalServerError(result.Error)
	}

	return nil
}

func (r *repositoryImpl) GetAllUsers(ctx context.Context) ([]entities.UserDetail, error) {
	var userDetails []entities.UserDetail

	err := r.db.WithContext(ctx).
		Table("users as u").
		Select(`
			u.id,
			u.role_id,
			r.name AS role,
			u.username,
			u.email,
			u.hash_password,
			u.created_at,
			u.updated_at`).
		Joins("LEFT JOIN roles r ON u.role_id = r.id").
		Find(&userDetails).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, app_errors.NotFound(app_errors.ErrUserNotFound)
	}
	if err != nil {
		return nil, app_errors.InternalServerError(err)
	}

	return userDetails, nil
}

func (r *repositoryImpl) GetAccessByUsername(ctx context.Context, username string, resource string) (constants.AccessLevel, error) {
	query := r.db.WithContext(ctx).
		Table("users u").
		Select(`p.access_level`).
		Joins(`JOIN roles r ON r.id = u.role_id`).
		Joins(`JOIN permissions p ON p.role_id = u.role_id`).
		Where("u.username = ?", username).
		Where("p.resource = ?", resource)

	var accessLevel string

	if err := query.Take(&accessLevel).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return constants.AccessLevel(accessLevel), app_errors.NotFound(app_errors.ErrPermissionNotFound)
		}

		return constants.AccessLevel(accessLevel), app_errors.InternalServerError(err)
	}

	return constants.AccessLevel(accessLevel), nil
}

func (r *repositoryImpl) GetNewRequestsByUsername(ctx context.Context, username string) ([]entities.PermissionReq, error) {
	var requests []entities.PermissionReq

	query := r.db.WithContext(ctx).
		Table("permission_requests pr").
		Select(`pr.id, pr.requester_id, pr.requestee_id, pr.resource, pr.created_at, pr.is_answered`).
		Joins("JOIN users u ON u.id = pr.requestee_id").
		Where("u.username = ?", username).
		Where("pr.is_answered = ?", false)

	if err := query.Find(&requests).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, app_errors.NotFound(app_errors.ErrRequestNotFound)
		}
		return nil, app_errors.InternalServerError(err)
	}

	return requests, nil
}

func (r *repositoryImpl) GetPermissionsByUsername(ctx context.Context, username string) ([]entities.PermissionReqResponse, error) {
	var permissions []entities.PermissionReqResponse

	err := r.db.WithContext(ctx).
		Table("permission_requests AS pr").
		Select(`distinct
      pr.resource,
      pr.created_at,
      p.required_signatures AS approves_needed,
      COUNT(CASE WHEN pr.is_answered = true THEN 1 END) AS answered,
      COUNT(CASE WHEN pr.is_answered = true AND pr.is_signed = true THEN 1 END) AS approves_given
    `).
		Joins("JOIN users u ON u.id = pr.requester_id").
		Joins("JOIN permissions p ON p.resource = pr.resource").
		Where("u.username = ? AND NOT p.required_signatures = 0", username).
		Group("pr.resource, pr.created_at, p.required_signatures").
		Order("pr.created_at DESC"). // Optional: order by time if needed
		Find(&permissions).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, app_errors.NotFound(app_errors.ErrPermissionNotFound)
		}
		return nil, app_errors.InternalServerError(err)
	}

	return permissions, nil
}

func (r *repositoryImpl) DeclineRequest(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).
		Table("permission_requests").
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"is_answered": true,
			"is_signed":   false,
			"updated_at":  time.Now(),
		}).Error
}

func (r *repositoryImpl) AcceptRequest(ctx context.Context, id string, signature []byte) error {
	signatureHex := hex.EncodeToString(signature)

	return r.db.WithContext(ctx).
		Table("permission_requests").
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"is_answered": true,
			"is_signed":   true,
			"signature":   signatureHex,
			"updated_at":  time.Now(),
		}).Error
}

func (r *repositoryImpl) GetHashedPublicKey(ctx context.Context, username string) (string, error) {
	var publicKey string
	err := r.db.WithContext(ctx).
		Table("users").
		Select("hash_public_key").
		Where("username = ?", username).
		Take(&publicKey).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", app_errors.NotFound(app_errors.ErrUserNotFound)
	}
	if err != nil {
		return "", app_errors.InternalServerError(err)
	}

	return publicKey, nil
}

func (r *repositoryImpl) GetResponsiblesIDsByResource(ctx context.Context, resource string) ([]string, error) {
	var roleIDs []string
	err := r.db.WithContext(ctx).
		Table("permissions").
		Select("role_id").
		Where("resource = ? AND access_level = ?", resource, "high_access").
		Find(&roleIDs).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, app_errors.NotFound(app_errors.ErrPermissionNotFound)
	}
	if err != nil {
		return nil, app_errors.InternalServerError(err)
	}

	var userIDs []string
	err = r.db.WithContext(ctx).
		Table("users").
		Select("id").
		Where("role_id IN ?", roleIDs).
		Find(&userIDs).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, app_errors.NotFound(app_errors.ErrUsersNotFound)
	}
	if err != nil {
		return nil, app_errors.InternalServerError(err)
	}

	return userIDs, nil
}

func (r *repositoryImpl) CreateRequests(ctx context.Context, username, resource string, responsiblesIDs []string) error {
	var requesterID string
	err := r.db.WithContext(ctx).
		Table("users").
		Select("id").
		Where("username = ?", username).
		Take(&requesterID).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return app_errors.NotFound(app_errors.ErrUserNotFound)
	}
	if err != nil {
		return app_errors.InternalServerError(err)
	}

	var requests []map[string]interface{}
	for _, requesteeID := range responsiblesIDs {
		requests = append(requests, map[string]interface{}{
			"id":           uuid.New().String(),
			"requester_id": requesterID,
			"requestee_id": requesteeID,
			"resource":     resource,
			"created_at":   time.Now(),
			"updated_at":   time.Now(),
		})
	}

	return r.db.WithContext(ctx).Table("permission_requests").Create(&requests).Error
}

func (r *repositoryImpl) GetSignedRequests(ctx context.Context, requestID string) ([]entities.PermissionReqSignature, error) {
	var results []entities.PermissionReqSignature

	err := r.db.WithContext(ctx).
		Table("permission_requests").
		Select("id, signature").
		Where("id = ? AND is_signed = true", requestID).
		Find(&results).Error

	if err != nil {
		return nil, app_errors.InternalServerError(err)
	}
	return results, nil
}

func (r *repositoryImpl) GetResource(ctx context.Context, requestID string) (string, error) {
	var resource string
	err := r.db.WithContext(ctx).
		Table("permission_requests").
		Select("resource").
		Where("id = ?", requestID).
		Take(&resource).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", app_errors.NotFound(app_errors.ErrRequestNotFound)
	}
	if err != nil {
		return "", app_errors.InternalServerError(err)
	}
	return resource, nil
}

func (r *repositoryImpl) GetRequiredSignatures(ctx context.Context, resource string) (int, error) {
	var required int
	err := r.db.WithContext(ctx).
		Table("permissions").
		Select("required_signatures").
		Where("resource = ?", resource).
		Limit(1).
		Take(&required).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, app_errors.NotFound(app_errors.ErrPermissionNotFound)
	}
	if err != nil {
		return 0, app_errors.InternalServerError(err)
	}
	return required, nil
}

func (r *repositoryImpl) StoreAggregatedApproval(ctx context.Context, requestID string, resource string, signature []byte) error {
	return r.db.WithContext(ctx).
		Table("aggregated_approvals").
		Create(map[string]interface{}{
			"request_id":           requestID,
			"resource":             resource,
			"aggregated_signature": signature,
			"created_at":           time.Now(),
		}).Error
}
