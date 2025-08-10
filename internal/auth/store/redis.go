package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-redis/redis/v8"
	"time"
)

type RedisClientStore struct {
	client *redis.Client
	crypto *CryptoManager
	prefix string
}

func NewRedisClientStore(redisClient *redis.Client, secretKey, prefix string) *RedisClientStore {
	if prefix == "" {
		prefix = "oauth:client:"
	}
	return &RedisClientStore{client: redisClient, crypto: NewCryptoManager(secretKey), prefix: prefix}
}

// Create stores a new OAuth client
func (s *RedisClientStore) Create(ctx context.Context, client *OAuthClient) error {
	key := s.prefix + client.ClientID

	// Check if client already exists
	exists, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to check client existence: %w", err)
	}
	if exists > 0 {
		return errors.New("client already exists")
	}

	// Encrypt client secret
	if client.ClientSecret != "" {
		encrypted, err := s.crypto.Encrypt(client.ClientSecret)
		if err != nil {
			return fmt.Errorf("failed to encrypt client secret: %w", err)
		}
		client.ClientSecret = encrypted
	}

	// Serialize client
	data, err := json.Marshal(client)
	if err != nil {
		return fmt.Errorf("failed to serialize client: %w", err)
	}

	// Store in Redis
	err = s.client.Set(ctx, key, data, 0).Err()
	if err != nil {
		return fmt.Errorf("failed to store client: %w", err)
	}

	// Set expiration if specified
	if client.ExpiresAt != nil {
		s.client.ExpireAt(ctx, key, *client.ExpiresAt)
	}

	return nil
}

// GetByID retrieves a client by its ID
func (s *RedisClientStore) GetByID(ctx context.Context, clientID string) (*OAuthClient, error) {
	key := s.prefix + clientID

	data, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.New("client not found")
		}
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	var client OAuthClient
	if err := json.Unmarshal([]byte(data), &client); err != nil {
		return nil, fmt.Errorf("failed to deserialize client: %w", err)
	}

	// Decrypt client secret
	if client.ClientSecret != "" {
		decrypted, err := s.crypto.Decrypt(client.ClientSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt client secret: %w", err)
		}
		client.ClientSecret = decrypted
	}

	return &client, nil
}

// Update updates an existing client
func (s *RedisClientStore) Update(ctx context.Context, client *OAuthClient) error {
	key := s.prefix + client.ClientID

	// Check if client exists
	exists, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to check client existence: %w", err)
	}
	if exists == 0 {
		return errors.New("client not found")
	}

	// Encrypt client secret
	if client.ClientSecret != "" {
		encrypted, err := s.crypto.Encrypt(client.ClientSecret)
		if err != nil {
			return fmt.Errorf("failed to encrypt client secret: %w", err)
		}
		client.ClientSecret = encrypted
	}

	client.UpdatedAt = time.Now()

	// Serialize client
	data, err := json.Marshal(client)
	if err != nil {
		return fmt.Errorf("failed to serialize client: %w", err)
	}

	// Store in Redis
	err = s.client.Set(ctx, key, data, 0).Err()
	if err != nil {
		return fmt.Errorf("failed to update client: %w", err)
	}

	// Set expiration if specified
	if client.ExpiresAt != nil {
		s.client.ExpireAt(ctx, key, *client.ExpiresAt)
	}

	return nil
}

// Delete removes a client by its ID
func (s *RedisClientStore) Delete(ctx context.Context, clientID string) error {
	key := s.prefix + clientID

	result, err := s.client.Del(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}
	if result == 0 {
		return errors.New("client not found")
	}

	return nil
}

// List returns all clients with pagination
func (s *RedisClientStore) List(ctx context.Context, offset, limit int) ([]*OAuthClient, int, error) {
	pattern := s.prefix + "*"

	// Get all client keys
	keys, err := s.client.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get client keys: %w", err)
	}

	total := len(keys)
	if offset >= total {
		return []*OAuthClient{}, total, nil
	}

	// Calculate pagination
	end := offset + limit
	if end > total {
		end = total
	}

	selectedKeys := keys[offset:end]
	if len(selectedKeys) == 0 {
		return []*OAuthClient{}, total, nil
	}

	// Get clients data
	data, err := s.client.MGet(ctx, selectedKeys...).Result()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get clients data: %w", err)
	}

	clients := make([]*OAuthClient, 0, len(data))
	for _, item := range data {
		if item == nil {
			continue
		}

		var client OAuthClient
		if err := json.Unmarshal([]byte(item.(string)), &client); err != nil {
			continue // Skip invalid clients
		}

		// Decrypt client secret
		if client.ClientSecret != "" {
			decrypted, err := s.crypto.Decrypt(client.ClientSecret)
			if err != nil {
				continue // Skip clients with decryption errors
			}
			client.ClientSecret = decrypted
		}

		clients = append(clients, &client)
	}

	return clients, total, nil
}

// GetByCredentials validates client credentials
func (s *RedisClientStore) GetByCredentials(ctx context.Context, clientID, clientSecret string) (*OAuthClient, error) {
	client, err := s.GetByID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// Validate client secret
	if client.TokenEndpointAuthMethod != "none" && client.ClientSecret != clientSecret {
		return nil, errors.New("invalid client credentials")
	}

	return client, nil
}

// CleanupExpired removes expired clients
func (s *RedisClientStore) CleanupExpired(ctx context.Context) (int, error) {
	pattern := s.prefix + "*"

	// Get all client keys
	keys, err := s.client.Keys(ctx, pattern).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get client keys: %w", err)
	}

	count := 0
	now := time.Now()

	for _, key := range keys {
		// Get TTL
		ttl, err := s.client.TTL(ctx, key).Result()
		if err != nil {
			continue
		}

		// Check if expired
		if ttl == -1 {
			// No expiration set, check client data
			data, err := s.client.Get(ctx, key).Result()
			if err != nil {
				continue
			}

			var client OAuthClient
			if err := json.Unmarshal([]byte(data), &client); err != nil {
				continue
			}

			if client.ExpiresAt != nil && client.ExpiresAt.Before(now) {
				s.client.Del(ctx, key)
				count++
			}
		}
	}

	return count, nil
}

// Close closes the storage connection
func (s *RedisClientStore) Close() error {
	return s.client.Close()
}
