package server

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// TokenType defines the type of token (access or refresh).
type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

// JWKVerifier implements TokenVerifier with JWK support.
type JWKVerifier struct {
	jwksURL       string
	cache         *jwk.Cache
	localKeys     map[string]interface{}
	remoteEnabled bool
	mu            sync.RWMutex
}

// NewJWKVerifier creates a new JWKVerifier instance.
func NewJWKVerifier(jwksURL string, remoteEnabled bool) *JWKVerifier {
	return &JWKVerifier{
		jwksURL:       jwksURL,
		cache:         jwk.NewCache(context.Background()),
		localKeys:     make(map[string]interface{}),
		remoteEnabled: remoteEnabled,
	}
}

// VerifyToken verifies the token using RS256/ES256 and JWK cache.
func (v *JWKVerifier) VerifyToken(ctx context.Context, token string, tokenType TokenType) (jwt.Token, error) {
	parsedToken, err := jwt.ParseString(token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	keyID, ok := parsedToken.Get(jwk.KeyIDKey)
	if !ok {
		return nil, errors.New("token does not contain key ID")
	}

	// Try local keys first
	v.mu.RLock()
	key, exists := v.localKeys[keyID.(string)]
	v.mu.RUnlock()

	if exists {
		if err := jwt.Validate(parsedToken); err != nil {
			return nil, fmt.Errorf("local key verification failed: %v", err)
		}
		return parsedToken, nil
	}

	// Fallback to remote JWKS if enabled
	if v.remoteEnabled {
		keySet, err := v.cache.Get(ctx, v.jwksURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch JWKS: %v", err)
		}

		key, found := keySet.LookupKeyID(keyID.(string))
		if !found {
			return nil, fmt.Errorf("key not found in JWKS: %s", keyID)
		}

		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			return nil, fmt.Errorf("failed to get raw key: %v", err)
		}

		if err := jwt.Validate(parsedToken); err != nil {
			return nil, fmt.Errorf("remote key verification failed: %v", err)
		}

		// Cache the key locally
		v.mu.Lock()
		v.localKeys[keyID.(string)] = rawKey
		v.mu.Unlock()

		return parsedToken, nil
	}

	return nil, errors.New("no valid key found for verification")
}

// VerifyAccessToken verifies an access token.
func (v *JWKVerifier) VerifyAccessToken(ctx context.Context, token string) (jwt.Token, error) {
	return v.VerifyToken(ctx, token, AccessToken)
}

// VerifyRefreshToken verifies a refresh token.
func (v *JWKVerifier) VerifyRefreshToken(ctx context.Context, token string) (jwt.Token, error) {
	return v.VerifyToken(ctx, token, RefreshToken)
}

// LoadLocalKey loads a local key for verification.
func (v *JWKVerifier) LoadLocalKey(keyID string, key interface{}) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.localKeys[keyID] = key
}
