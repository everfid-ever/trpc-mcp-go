package store

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/go-redis/redis/v8"
)

// ClientStoreConfig represents client store configuration
type ClientStoreConfig struct {
	Type      string `json:"type" yaml:"type"`             // memory, redis, postgres
	SecretKey string `json:"secret_key" yaml:"secret_key"` // Encryption key

	// Redis configuration
	RedisAddr     string `json:"redis_addr" yaml:"redis_addr"`
	RedisPassword string `json:"redis_password" yaml:"redis_password"`
	RedisDB       int    `json:"redis_db" yaml:"redis_db"`
	RedisPrefix   string `json:"redis_prefix" yaml:"redis_prefix"`

	// PostgreSQL configuration
	PostgresHost     string `json:"postgres_host" yaml:"postgres_host"`
	PostgresPort     int    `json:"postgres_port" yaml:"postgres_port"`
	PostgresUser     string `json:"postgres_user" yaml:"postgres_user"`
	PostgresPassword string `json:"postgres_password" yaml:"postgres_password"`
	PostgresDatabase string `json:"postgres_database" yaml:"postgres_database"`
	PostgresSSLMode  string `json:"postgres_ssl_mode" yaml:"postgres_ssl_mode"`
}

// NewClientStore creates a new client store based on configuration
func NewClientStore(config *ClientStoreConfig) (ClientStore, error) {
	switch config.Type {
	case "memory":
		return NewMemoryClientStore(config.SecretKey), nil

	case "redis":
		redisClient := redis.NewClient(&redis.Options{
			Addr:     config.RedisAddr,
			Password: config.RedisPassword,
			DB:       config.RedisDB,
		})

		// Test connection
		if err := redisClient.Ping(context.Background()).Err(); err != nil {
			return nil, fmt.Errorf("failed to connect to Redis: %w", err)
		}

		return NewRedisClientStore(redisClient, config.SecretKey, config.RedisPrefix), nil

	case "postgres":
		dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
			config.PostgresHost, config.PostgresPort, config.PostgresUser,
			config.PostgresPassword, config.PostgresDatabase, config.PostgresSSLMode)

		db, err := sql.Open("postgres", dsn)
		if err != nil {
			return nil, fmt.Errorf("failed to open PostgreSQL connection: %w", err)
		}

		// Test connection
		if err := db.Ping(); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to ping PostgreSQL: %w", err)
		}

		// Run migrations
		if _, err := db.Exec(PostgreSQLSchema); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to run migrations: %w", err)
		}

		return NewPostgresClientStore(db, config.SecretKey), nil

	default:
		return nil, fmt.Errorf("unsupported store type: %s", config.Type)
	}
}
