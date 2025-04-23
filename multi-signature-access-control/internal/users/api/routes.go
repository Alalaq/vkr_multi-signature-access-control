package api

import (
	"github.com/labstack/echo/v4"
	"multi-signature-access-control/internal/middlewares"
)

func MapUserRoutes(g *echo.Group, h Handlers, mw *middlewares.Middleware) {
	g.POST("/register", h.RegisterHandler)
	g.POST("/login", h.LoginHandler)
	g.POST("/users", h.CreateUserHandler, mw.JWTMiddleware(), mw.MultiSigMiddleware("create"))
	g.GET("/get_all", h.GetAllUsersHandler, mw.JWTMiddleware(), mw.MultiSigMiddleware("get_all"))
	g.GET("/get_requests", h.GetNewRequestsHandler, mw.JWTMiddleware())
	g.PATCH("/sig_request", h.SignRequestHandler, mw.JWTMiddleware())
	g.PATCH("/decline_request", h.DeclineRequestHandler, mw.JWTMiddleware())
	g.GET("/get_permission_requests", h.GetPermissionRequestsHandler, mw.JWTMiddleware())
}
