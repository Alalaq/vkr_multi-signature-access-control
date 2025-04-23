package datasources

import (
	"context"

	"github.com/go-redis/redis/v8"
	"multi-signature-access-control/config"
)

func NewRedisClient(ctx context.Context, cfg config.RedisConfig) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
	})

	if err := client.Ping(ctx).Err(); err != nil {
		panic(err)
	}

	return client
}
