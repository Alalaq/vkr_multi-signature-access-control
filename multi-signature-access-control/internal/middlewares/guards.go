package middlewares

import (
	"errors"
	"github.com/labstack/echo/v4"
	"multi-signature-access-control/internal/users/usecase"
	"multi-signature-access-control/pkg/app_errors"
	"multi-signature-access-control/pkg/constants"
	"multi-signature-access-control/pkg/response"
	"multi-signature-access-control/pkg/security"
	"net/http"
)

type Middleware struct {
	jwt *security.JWTFactory
	uc  usecase.Usecase
}

func NewMiddleware(jwt *security.JWTFactory, uc usecase.Usecase) *Middleware {
	return &Middleware{jwt: jwt, uc: uc}
}
func (m *Middleware) JWTMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			tokenString := c.Request().Header.Get(constants.AuthorizationHeaderKey.String())
			if tokenString == "" {
				return response.ErrorBuilder(app_errors.Unauthorized(app_errors.ErrMissingJWTToken)).Send(c)
			}

			tokenString = tokenString[len("Bearer "):]
			if m.jwt.IsTokenBlacklisted(c.Request().Context(), tokenString) {
				return response.ErrorBuilder(app_errors.Unauthorized(app_errors.ErrInvalidJWTToken)).Send(c)
			}

			jwtClaims, err := m.jwt.VerifyJWT(tokenString)
			if err != nil {
				return response.ErrorBuilder(err).Send(c)
			}
			c.Set(constants.AuthCredentialContextKey.String(), jwtClaims)

			return next(c)
		}
	}
}

// MultiSigMiddleware handles multi-signature access logic
func (m *Middleware) MultiSigMiddleware(resource string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx := c.Request().Context()

			username := c.Request().Header.Get(constants.UsernameHeaderKey.String())

			requests, err := m.uc.GetPermissionRequests(ctx, username)
			if err != nil {
				return response.ErrorBuilder(err).Send(c)
			}

			for _, request := range requests {
				if request.Resource == resource {
					if request.ApprovesGiven == request.ApprovesNeeded {
						err = m.uc.DeleteRequest(ctx, username, resource)
						if err != nil {
							return response.ErrorBuilder(err).Send(c)
						}
						return next(c)
					} else if request.ApprovesNeeded == request.Answered {
						err = m.uc.DeleteRequest(ctx, username, resource)
						if err != nil {
							return response.ErrorBuilder(err).Send(c)
						}
						return response.ErrorBuilder(app_errors.Unauthorized(errors.New("request to resource was declined"))).Send(c)
					} else {
						return c.JSON(http.StatusProcessing, map[string]string{
							"message": "not all approves has been given yet, please wait",
						})
					}
				}
			}

			accessLevel, err := m.uc.GetAccessByUsername(ctx, username, resource)
			if err != nil {
				return response.ErrorBuilder(err).Send(c)
			}

			switch accessLevel {
			case constants.NoAccess:
				return response.ErrorBuilder(app_errors.Forbidden(app_errors.ErrAccessDenied)).Send(c)
			case constants.LowAccessLevel:
				responsibles, err := m.uc.GetResponsiblesIDsByResource(ctx, resource)
				if err != nil {
					return response.ErrorBuilder(err).Send(c)
				}
				err = m.uc.SendRequests(ctx, responsibles, resource, username)
				if err != nil {
					return response.ErrorBuilder(err).Send(c)
				}
				return c.JSON(http.StatusProcessing, map[string]string{
					"message": "requests to resource have been sent, please, wait",
				})
			case constants.HighAccessLevel:
				return next(c)
			}

			return next(c)
		}
	}
}
