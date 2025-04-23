package datasources

import (
	"context"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/plugin/opentelemetry/tracing"
	"multi-signature-access-control/config"
)

func NewMySQLDB(ctx context.Context, cfg config.DatabaseConfig) *gorm.DB {
	otps := &gorm.Config{SkipDefaultTransaction: true}

	if !cfg.Debug {
		otps = &gorm.Config{SkipDefaultTransaction: true, Logger: logger.Default.LogMode(logger.Silent)}
	}

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8&parseTime=true&loc=Europe%%2FMoscow&multiStatements=true", cfg.UserName, cfg.Password, cfg.Host, cfg.Port, cfg.DBName)
	db, err := gorm.Open(mysql.Open(dsn), otps)
	if err != nil {
		panic(err)
	}

	if err := db.Use(tracing.NewPlugin()); err != nil {
		panic(err)
	}

	return db
}
