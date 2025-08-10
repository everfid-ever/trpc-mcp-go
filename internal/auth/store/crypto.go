package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"time"
)

// CryptoManager handles encryption/decryption of sensitive data
type CryptoManager struct {
	key []byte
}

// NewCryptoManager creates a new crypto manager
func NewCryptoManager(secretKey string) *CryptoManager {
	hash := sha256.Sum256([]byte(secretKey))
	return &CryptoManager{key: hash[:]}
}

// Encrypt encrypts plaintext using AES-GCM
func (c *CryptoManager) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext using AES-GCM
func (c *CryptoManager) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext2 := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext2, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// CleanupExpired removes expired clients
func (s *MemoryClientStore) CleanupExpired(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	count := 0

	for clientID, client := range s.clients {
		if client.ExpiresAt != nil && client.ExpiresAt.Before(now) {
			delete(s.clients, clientID)
			count++
		}
	}

	return count, nil
}

// Close closes the storage connection
func (s *MemoryClientStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients = make(map[string]*OAuthClient)
	return nil
}
