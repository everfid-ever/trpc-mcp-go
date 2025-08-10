package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type MemoryClientStore struct {
	clients map[string]*OAuthClient
	mu      sync.RWMutex
	crypto  *CryptoManager
}

func NewMemoryClientStore(secretKey string) *MemoryClientStore {
	return &MemoryClientStore{
		clients: make(map[string]*OAuthClient),
		crypto:  NewCryptoManager(secretKey),
	}
}

// Create stores a new OAuth client
func (s *MemoryClientStore) Create(ctx context.Context, client *OAuthClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.clients[client.ClientID]; exists {
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

	s.clients[client.ClientID] = client
	return nil
}

// GetByID retrieves a client by its ID
func (s *MemoryClientStore) GetByID(ctx context.Context, clientID string) (*OAuthClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, exists := s.clients[clientID]
	if !exists {
		return nil, errors.New("client not found")
	}

	// Decrypt client secret
	decryptedClient := *client
	if client.ClientSecret != "" {
		decrypted, err := s.crypto.Decrypt(client.ClientSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt client secret: %w", err)
		}
		decryptedClient.ClientSecret = decrypted
	}

	return &decryptedClient, nil
}

// Update updates an existing client
func (s *MemoryClientStore) Update(ctx context.Context, client *OAuthClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.clients[client.ClientID]; !exists {
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
	s.clients[client.ClientID] = client
	return nil
}

// Delete removes a client by its ID
func (s *MemoryClientStore) Delete(ctx context.Context, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.clients[clientID]; !exists {
		return errors.New("client not found")
	}

	delete(s.clients, clientID)
	return nil
}

// List returns all clients with pagination
func (s *MemoryClientStore) List(ctx context.Context, offset, limit int) ([]*OAuthClient, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.clients)
	clients := make([]*OAuthClient, 0, limit)

	i := 0
	for _, client := range s.clients {
		if i >= offset && len(clients) < limit {
			// Decrypt client secret
			decryptedClient := *client
			if client.ClientSecret != "" {
				decrypted, err := s.crypto.Decrypt(client.ClientSecret)
				if err != nil {
					return nil, 0, fmt.Errorf("failed to decrypt client secret: %w", err)
				}
				decryptedClient.ClientSecret = decrypted
			}
			clients = append(clients, &decryptedClient)
		}
		i++
	}

	return clients, total, nil
}

// GetByCredentials validates client credentials
func (s *MemoryClientStore) GetByCredentials(ctx context.Context, clientID, clientSecret string) (*OAuthClient, error) {
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
