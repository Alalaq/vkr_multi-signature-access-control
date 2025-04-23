package dtos

import (
	"multi-signature-access-control/internal/users/entities"
	"time"

	"multi-signature-access-control/pkg/constants"
	"multi-signature-access-control/pkg/types"
)

type LoginRequest struct {
	Email    string       `json:"email" validate:"required,email"`
	Password types.Secret `json:"password" validate:"required"`
}

type LoginResponse struct {
	User        LoginData `json:"user"`
	AccessToken string    `json:"access_token"`
}

type LoginData struct {
	UserID    string             `json:"id"`
	Email     string             `json:"email"`
	Role      constants.UserRole `json:"role"`
	CreatedAt time.Time          `json:"created_at"`
	UpdatedAt *time.Time         `json:"updated_at"`
}

func MapLoginResponse(ud entities.UserDetail) LoginResponse {
	return LoginResponse{
		User: LoginData{
			UserID:    ud.ID,
			Email:     ud.Email,
			Role:      ud.Role,
			CreatedAt: ud.CreatedAt,
			UpdatedAt: ud.UpdatedAt,
		},
	}
}
