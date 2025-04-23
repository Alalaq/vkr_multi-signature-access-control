package entities

import (
	"time"

	"multi-signature-access-control/pkg/constants"
)

type UserDetailRequest struct {
	ID    *string
	Email *string
}

type UserDetailOpts func(*UserDetailRequest)

func WithEmail(email string) UserDetailOpts {
	return func(udr *UserDetailRequest) {
		udr.Email = &email
	}
}

type UserDetail struct {
	ID        string             `gorm:"column:id"`
	RoleID    string             `gorm:"column:role_id"`
	Role      constants.UserRole `gorm:"column:role"`
	Username  string             `gorm:"column:username"`
	Email     string             `gorm:"column:email"`
	Password  string             `gorm:"column:hash_password"`
	PublicKey string             `gorm:"column:hash_public_key"`
	CreatedAt time.Time          `gorm:"column:created_at"`
	UpdatedAt *time.Time         `gorm:"column:updated_at"`
}
