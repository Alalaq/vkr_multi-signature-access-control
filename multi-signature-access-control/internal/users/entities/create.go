package entities

import (
	"time"
)

type CreateUser struct {
	ID        string    `gorm:"column:id;primaryKey"`
	Username  string    `gorm:"column:username"`
	Email     string    `gorm:"column:email"`
	Password  string    `gorm:"column:password"`
	RoleID    string    `gorm:"column:role_id"`
	PublicKey string    `gorm:"column:public_key"`
	CreatedAt time.Time `gorm:"column:created_at"`
}

func (cu *CreateUser) SetRoleID(roleID string) {
	cu.RoleID = roleID
}

func (cu *CreateUser) SetPassword(hashedPassword string) {
	cu.Password = hashedPassword
}
