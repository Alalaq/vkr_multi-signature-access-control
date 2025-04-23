package server

import (
	"fmt"
	"multi-signature-access-control/internal/users/api"
	"net/http"

	"multi-signature-access-control/internal/middlewares"
	userRepo "multi-signature-access-control/internal/users/repository"
	userUsecase "multi-signature-access-control/internal/users/usecase"
	"multi-signature-access-control/pkg/redis"
	"multi-signature-access-control/pkg/security"

	"github.com/labstack/echo/v4"
	echoSwagger "github.com/swaggo/echo-swagger"
)

func (s *Server) mapHandler() error {
	// Define the domain and create a versioned group for API endpoints.
	var domain = s.echo.Group("")

	{
		domain.GET("/ping", func(c echo.Context) error {
			return c.JSON(http.StatusOK, fmt.Sprintf("welcome to Multi Signature PrivateKey and Scope Based Access Control (MSRBAC) version %s", s.cfg.App.Version))
		})

		// Serve Swagger documentation
		domain.GET("/swagger/*", echoSwagger.WrapHandler)
	}

	repository := userRepo.NewUsersRepository(s.db)
	redisDB := redis.NewRedis(s.redisConn)
	sec := security.NewJWTFactory(s.cfg.Security.JWT, redisDB)
	uc := userUsecase.NewUsecase(repository, sec)
	mw := middlewares.NewMiddleware(sec, uc)
	handler := api.NewUsersHandler(uc)
	api.MapUserRoutes(domain, handler, mw)

	return nil
}
