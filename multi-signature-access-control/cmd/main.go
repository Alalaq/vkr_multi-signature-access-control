package main

import (
	"context"
	"github.com/labstack/gommon/log"
	"multi-signature-access-control/config"
	"multi-signature-access-control/docs"
	"multi-signature-access-control/internal/server"
	"strings"
	"time"
)

// main is entrypoint of application
//
//	@title	Go PrivateKey and Scope Based Access Control (RBAC)
//	@description.markdown
//	@termsOfService				https://multi-signature-access-control
//	@BasePath					/api/v1/msrbac
//
//	@securityDefinitions.apiKey	BearerToken
//	@in							header
//	@name						Authorization
func main() {
	// Load the application configuration from the specified directory.

	cfg, err := config.LoadConfig("config")
	if err != nil {
		panic(err)
	}

	// make swagger host dynamic.
	docs.SwaggerInfo.Host = cfg.App.Host
	docs.SwaggerInfo.Schemes = strings.Split(cfg.App.Scheme, ",")
	docs.SwaggerInfo.Version = cfg.App.Version

	if _, err := time.LoadLocation(cfg.Server.TimeZone); err != nil {
		panic(err)
	}

	// Create a new instance of the application and start it.
	if err := server.NewServer(context.Background(), cfg).Run(); err != nil {
		log.Warn(err)
	}
}
