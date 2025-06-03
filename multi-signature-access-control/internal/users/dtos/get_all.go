package dtos

import (
	"crypto/ecdsa"
	"multi-signature-access-control/internal/users/entities"
	"multi-signature-access-control/pkg/constants"
	"time"
)

type GetUsersRequest struct {
	Username string `json:"username" validate:"required"`
	Email    string `json:"email" validate:"required,email"`
	//Password   types.Secret       `json:"password" validate:"required"`
	PrivateKey *ecdsa.PrivateKey `json:"private_key" validate:"required"`
}

type GetUsersResponse struct {
	Users []UserData `json:"users"`
}

func NewGetUsersResponse(userDetails []entities.UserDetail) GetUsersResponse {
	return userDetailsToGetUsersResponse(userDetails)
}

func userDetailToUserData(user entities.UserDetail) UserData {
	return UserData{
		ID:        user.ID,
		RoleID:    user.RoleID,
		Role:      user.Role,
		Username:  user.Username,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}

func userDetailsToGetUsersResponse(userDetails []entities.UserDetail) GetUsersResponse {
	users := make([]UserData, len(userDetails))
	for i, user := range userDetails {
		users[i] = userDetailToUserData(user)
	}
	return GetUsersResponse{Users: users}
}

type UserData struct {
	ID        string             `json:"id"`
	RoleID    string             `json:"role_id"`
	Role      constants.UserRole `json:"role"`
	Username  string             `json:"username"`
	Email     string             `json:"email"`
	CreatedAt time.Time          `json:"created_at"`
	UpdatedAt *time.Time         `json:"updated_at"`
}
