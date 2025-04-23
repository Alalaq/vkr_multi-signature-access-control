package usecase

import (
	"context"
	"errors"
	"multi-signature-access-control/internal/middlewares/accesscontrol"
	"multi-signature-access-control/internal/users/repository"
	"multi-signature-access-control/pkg/constants"
	"slices"

	"multi-signature-access-control/internal/users/dtos"
	"multi-signature-access-control/internal/users/entities"
	"multi-signature-access-control/pkg/app_errors"
	"multi-signature-access-control/pkg/security"
	"multi-signature-access-control/pkg/utils"
)

type Usecase interface {
	Login(ctx context.Context, request dtos.LoginRequest) (dtos.LoginResponse, error)
	Create(ctx context.Context, request dtos.CreateUserRequest) error
	GetAllUsers(ctx context.Context) (dtos.GetUsersResponse, error)
	GetNewRequestsByUsername(ctx context.Context, username string) ([]entities.RecentPermissionReqResponse, error)
	GetPermissionRequests(ctx context.Context, username string) ([]entities.PermissionReqResponse, error)
	DeclineRequest(ctx context.Context, request dtos.PermissionReqRequest) error
	SignRequest(ctx context.Context, request dtos.PermissionReqRequest) error
	GetAccessByUsername(ctx context.Context, username string, resource string) (constants.AccessLevel, error)
	GetResponsiblesIDsByResource(ctx context.Context, resource string) ([]string, error)
	SendRequests(ctx context.Context, responsibles []string, resource, username string) error
	Register(ctx context.Context, request dtos.RegisterRequest) (dtos.RegisterResponse, error)
	DeleteRequest(ctx context.Context, username string, resource string) error
}

type usecase struct {
	repo     repository.Repository
	security *security.JWTFactory
}

func NewUsecase(repo repository.Repository, security *security.JWTFactory) Usecase {
	return &usecase{
		repo:     repo,
		security: security,
	}
}

func (uc *usecase) Register(ctx context.Context, request dtos.RegisterRequest) (dtos.RegisterResponse, error) {
	var response dtos.RegisterResponse
	keys, err := accesscontrol.GenerateKey()
	if err != nil {
		return response, err
	}

	stringKey := accesscontrol.PublicKeyToString(keys.PublicKey)
	hashKey, err := utils.EncryptSecret(stringKey)
	if err != nil {
		return response, err
	}

	newUser := dtos.NewCreateUserFromRegister(request, hashKey)
	if request.HasPassword() {
		hashedPassword, err := utils.EncryptSecret(request.Password.String())
		if err != nil {
			return response, err
		}

		newUser.SetPassword(hashedPassword)
	}

	newUser.SetRoleID(string(constants.Employee))

	creteadUser, err := uc.repo.CreateUser(ctx, newUser)
	if err != nil {
		return response, app_errors.InternalServerError(err)
	}

	response = dtos.MapRegisterResponse(creteadUser, accesscontrol.PrivateKeyToString(keys.PrivateKey))

	response.AccessToken, err = uc.security.CreateJWT(creteadUser.ID, creteadUser.RoleID, response.User.Role)
	if err != nil {
		return response, err
	}

	return response, nil
}

func (uc *usecase) Login(ctx context.Context, request dtos.LoginRequest) (dtos.LoginResponse, error) {
	userDetail, err := uc.repo.Detail(ctx, entities.WithEmail(request.Email))
	if err != nil {
		if errors.Is(err, app_errors.ErrUserNotFound) {
			return dtos.LoginResponse{}, app_errors.BadRequest(app_errors.ErrYourEmailWrong)
		}

		return dtos.LoginResponse{}, err
	}

	if !utils.CheckSecretHash(request.Password.String(), userDetail.Password) {
		return dtos.LoginResponse{}, app_errors.BadRequest(app_errors.ErrYourPasswordWrong)
	}

	response := dtos.MapLoginResponse(userDetail)

	response.AccessToken, err = uc.security.CreateJWT(userDetail.ID, userDetail.RoleID, response.User.Role)
	if err != nil {
		return response, err
	}

	return response, nil
}

func (uc *usecase) Create(ctx context.Context, request dtos.CreateUserRequest) error {
	keys, err := accesscontrol.GenerateKey()
	if err != nil {
		return err
	}

	stringKey := accesscontrol.PublicKeyToString(keys.PublicKey)
	hashKey, err := utils.EncryptSecret(stringKey)
	if err != nil {
		return err
	}

	newUser := dtos.NewCreateUser(request, hashKey)
	if request.HasPassword() {
		hashedPassword, err := utils.EncryptSecret(request.Password.String())
		if err != nil {
			return err
		}

		newUser.SetPassword(hashedPassword)
	}

	exist := slices.Contains(constants.RoleIDs, request.RoleId)
	if !exist {
		return app_errors.BadRequest(app_errors.ErrInvalidRole)
	}
	newUser.SetRoleID(request.RoleId.String())

	return uc.repo.Create(ctx, newUser)
}

func (uc *usecase) GetAllUsers(ctx context.Context) (dtos.GetUsersResponse, error) {
	userDetails, err := uc.repo.GetAllUsers(ctx)
	if err != nil {
		return dtos.GetUsersResponse{}, err
	}
	return dtos.NewGetUsersResponse(userDetails), nil
}

func (uc *usecase) GetNewRequestsByUsername(ctx context.Context, username string) ([]entities.RecentPermissionReqResponse, error) {
	reqs, err := uc.repo.GetNewRequestsByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	return entities.MapPermReqsToResponse(reqs), nil
}

func (uc *usecase) GetPermissionRequests(ctx context.Context, username string) ([]entities.PermissionReqResponse, error) {
	resp, err := uc.repo.GetPermissionsByUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (uc *usecase) DeclineRequest(ctx context.Context, request dtos.PermissionReqRequest) error {
	if err := uc.repo.DeclineRequest(ctx, request.RequestID); err != nil {
		return err
	}
	return nil
}

func (uc *usecase) SignRequest(ctx context.Context, request dtos.PermissionReqRequest) error {
	privKey, err := accesscontrol.StringToPrivateKey(request.PrivateKey)
	if err != nil {
		return err
	}
	signature, err := accesscontrol.Sign(request.RequestID, privKey)
	if err != nil {
		return err
	}

	hashedPubKey, err := uc.repo.GetHashedPublicKey(ctx, request.Username)
	if err != nil {
		return err
	}

	pubkeyStr, err := utils.DecryptSecret(hashedPubKey)
	if err != nil {
		return err
	}

	pubKey, err := accesscontrol.StringToPublicKey(pubkeyStr)
	if err != nil {
		return err
	}

	if !accesscontrol.Verify(request.RequestID, signature, *pubKey) {
		return app_errors.ErrInvalidSignature
	}
	if err := uc.repo.AcceptRequest(ctx, request.RequestID); err != nil {
		return err
	}
	return nil
}

func (uc *usecase) GetAccessByUsername(ctx context.Context, username string, resource string) (constants.AccessLevel, error) {
	access, err := uc.repo.GetAccessByUsername(ctx, username, resource)
	if err != nil {
		return "", err
	}
	return access, nil
}

func (uc *usecase) GetResponsiblesIDsByResource(ctx context.Context, resource string) ([]string, error) {
	responsiblesIDs, err := uc.repo.GetResponsiblesIDsByResource(ctx, resource)
	if err != nil {
		return []string{}, err
	}
	return responsiblesIDs, nil
}

func (uc *usecase) SendRequests(ctx context.Context, responsiblesIDs []string, resource, username string) error {
	err := uc.repo.CreateRequests(ctx, username, resource, responsiblesIDs)
	return err
}

func (uc *usecase) DeleteRequest(ctx context.Context, username string, resource string) error {
	err := uc.repo.DeleteRequest(ctx, username, resource)

	return err
}
