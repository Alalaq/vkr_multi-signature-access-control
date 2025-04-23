package security

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"multi-signature-access-control/config"
	"multi-signature-access-control/pkg/app_errors"
	"multi-signature-access-control/pkg/constants"
	"multi-signature-access-control/pkg/redis"
)

// JWTClaims defines the structure of the data stored in the JWT token
type JWTClaims struct {
	UserID      string                    `json:"user_id"`     // User ID
	RoleID      string                    `json:"role_id"`     // Role ID
	Role        constants.UserRole        `json:"role"`        // Role name (e.g., "Admin", "Employee")
	Permissions []constants.JWTPermission `json:"permissions"` // List of permissions associated with the role
	Exp         int64                     `json:"exp"`         // Expiration time of the token (Unix timestamp)

	// Standard JWT Claims
	jwt.RegisteredClaims
}

type JWTFactory struct {
	cfg   config.JWTConfig
	redis redis.Redis
}

func NewJWTFactory(c config.JWTConfig, r redis.Redis) *JWTFactory {
	return &JWTFactory{c, r}
}

func (f *JWTFactory) CreateJWT(userID, roleID string, role constants.UserRole, permissions ...constants.JWTPermission) (string, error) {
	claims := JWTClaims{
		UserID:      userID,
		RoleID:      roleID,
		Role:        role,
		Permissions: permissions,
		Exp:         time.Now().Add(time.Duration(f.cfg.ExpiredInSecond) * time.Second).Unix(),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(f.cfg.ExpiredInSecond) * time.Second)),
		},
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(f.cfg.Key))
}

func (f *JWTFactory) VerifyJWT(tokenString string) (*JWTClaims, error) {
	// Parse and validate the token
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Return the secret key for validation
		return []byte(f.cfg.Key), nil
	})

	if err != nil {
		return nil, app_errors.Unauthorized(app_errors.ErrInvalidJWTToken)
	}

	if !token.Valid {
		return nil, app_errors.Unauthorized(app_errors.ErrJWTTokenNotValid)
	}

	return token.Claims.(*JWTClaims), nil
}

func (f *JWTFactory) AddToBlacklist(context context.Context, token string, expiration time.Time) error {
	return f.redis.Set(context, token, constants.BlacklistedToken, time.Until(expiration))
}

func (f *JWTFactory) IsTokenBlacklisted(ctx context.Context, key string) bool {
	revoked, err := f.redis.Get(ctx, key)
	if err != nil {
		return false
	}

	return revoked == constants.BlacklistedToken
}
