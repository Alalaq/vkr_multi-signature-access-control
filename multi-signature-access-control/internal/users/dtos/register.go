package dtos

import (
	"github.com/google/uuid"
	"multi-signature-access-control/internal/users/entities"
	"time"

	"multi-signature-access-control/pkg/constants"
	"multi-signature-access-control/pkg/types"
)

type RegisterRequest struct {
	Email    string       `json:"email" validate:"required,email"`
	Username string       `json:"username" validate:"required"`
	Password types.Secret `json:"password" validate:"required"`
}

type RegisterResponse struct {
	User        RegisterData `json:"user"`
	AccessToken string       `json:"access_token"`
}

type RegisterData struct {
	Email      string             `json:"email"`
	Username   string             `json:"username"`
	PrivateKey string             `json:"private_key"`
	Role       constants.UserRole `json:"role"`
	CreatedAt  time.Time          `json:"created_at"`
	UpdatedAt  *time.Time         `json:"updated_at"`
}

func MapRegisterResponse(ud entities.UserDetail, key string) RegisterResponse {
	return RegisterResponse{
		User: RegisterData{
			Email:      ud.Email,
			Username:   ud.Username,
			PrivateKey: key,
			Role:       ud.Role,
			CreatedAt:  ud.CreatedAt,
			UpdatedAt:  ud.UpdatedAt,
		},
	}
}

func NewCreateUserFromRegister(request RegisterRequest, pk string) *entities.CreateUser {
	return &entities.CreateUser{
		ID:        uuid.New().String(),
		Username:  request.Username,
		Email:     request.Email,
		CreatedAt: time.Now(),
		PublicKey: pk,
	}
}

func (rr RegisterRequest) HasPassword() bool {
	return rr.Password != ""
}
