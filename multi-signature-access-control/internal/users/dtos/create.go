package dtos

import (
	"github.com/google/uuid"
	"multi-signature-access-control/internal/users/entities"
	"multi-signature-access-control/pkg/constants"
	"multi-signature-access-control/pkg/types"
	"time"
)

type CreateUserRequest struct {
	Username string               `json:"username" validate:"required"`
	Email    string               `json:"email" validate:"required,email"`
	Password types.Secret         `json:"password" validate:"required"`
	RoleId   constants.UserRoleID `json:"role_id" validate:"required"`
}

func NewCreateUser(request CreateUserRequest, pk string) *entities.CreateUser {
	return &entities.CreateUser{
		ID:        uuid.New().String(),
		Username:  request.Username,
		Email:     request.Email,
		CreatedAt: time.Now(),
		PublicKey: pk,
	}
}

func (cur CreateUserRequest) HasPassword() bool {
	return cur.Password != ""
}
