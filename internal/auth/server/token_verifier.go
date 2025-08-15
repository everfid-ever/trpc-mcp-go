package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
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

// JWKVerifier implements TokenVerifier with JWK support and returns AuthInfo directly.
type JWKVerifier struct {
	jwksURL       string
	cache         *jwk.Cache
	localKeys     jwk.Set
	remoteEnabled bool
	mu            sync.RWMutex
}

// NewJWKVerifier creates a new JWKVerifier instance.
func NewJWKVerifier(jwksURL string, remoteEnabled bool) *JWKVerifier {
	return &JWKVerifier{
		jwksURL:       jwksURL,
		cache:         jwk.NewCache(context.Background()),
		localKeys:     jwk.NewSet(),
		remoteEnabled: remoteEnabled,
	}
}

// VerifyToken verifies the token using RS256/ES256 and JWK cache, returns parsed and verified jwt.Token.
func (v *JWKVerifier) VerifyToken(ctx context.Context, token string, tokenType TokenType) (jwt.Token, error) {
	// First, try to parse with local keys
	v.mu.RLock()
	localKeys := v.localKeys
	v.mu.RUnlock()

	if localKeys.Len() > 0 {
		parsedToken, err := jwt.Parse([]byte(token), jwt.WithKeySet(localKeys))
		if err == nil {
			return parsedToken, nil
		}
		// If local verification fails, continue to remote
	}

	// Fallback to remote JWKS if enabled
	if v.remoteEnabled && v.jwksURL != "" {
		keySet, err := v.cache.Get(ctx, v.jwksURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch JWKS: %v", err)
		}

		parsedToken, err := jwt.Parse([]byte(token), jwt.WithKeySet(keySet))
		if err != nil {
			return nil, fmt.Errorf("remote key verification failed: %v", err)
		}

		// Cache successful keys locally
		v.cacheRemoteKey(parsedToken, keySet)

		return parsedToken, nil
	}

	return nil, errors.New("no valid key found for verification")
}

// VerifyAccessToken verifies an access token and returns AuthInfo directly.
// 注意：返回值改为 AuthInfo 而不是 *AuthInfo，以匹配接口定义
func (v *JWKVerifier) VerifyAccessToken(token string) (AuthInfo, error) {
	ctx := context.Background()

	// Verify the JWT token
	jwtToken, err := v.VerifyToken(ctx, token, AccessToken)
	if err != nil {
		return AuthInfo{}, fmt.Errorf("token verification failed: %w", err)
	}

	// Convert jwt.Token to AuthInfo
	authInfo, err := v.convertJWTToAuthInfo(jwtToken, token)
	if err != nil {
		return AuthInfo{}, fmt.Errorf("failed to convert JWT to AuthInfo: %w", err)
	}

	return authInfo, nil
}

// VerifyRefreshToken verifies a refresh token and returns AuthInfo.
func (v *JWKVerifier) VerifyRefreshToken(token string) (AuthInfo, error) {
	ctx := context.Background()

	// Verify the JWT token
	jwtToken, err := v.VerifyToken(ctx, token, RefreshToken)
	if err != nil {
		return AuthInfo{}, fmt.Errorf("token verification failed: %w", err)
	}

	// Convert jwt.Token to AuthInfo
	authInfo, err := v.convertJWTToAuthInfo(jwtToken, token)
	if err != nil {
		return AuthInfo{}, fmt.Errorf("failed to convert JWT to AuthInfo: %w", err)
	}

	return authInfo, nil
}

// cacheRemoteKey extracts and caches the key used for verification
func (v *JWKVerifier) cacheRemoteKey(jwtToken jwt.Token, keySet jwk.Set) {
	keyID, ok := jwtToken.Get(jwk.KeyIDKey)
	if !ok {
		return
	}

	keyIDStr, ok := keyID.(string)
	if !ok {
		return
	}

	key, found := keySet.LookupKeyID(keyIDStr)
	if !found {
		return
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// Add key to local set
	v.localKeys.AddKey(key)
}

// convertJWTToAuthInfo converts jwt.Token to AuthInfo structure.
func (v *JWKVerifier) convertJWTToAuthInfo(jwtToken jwt.Token, token string) (AuthInfo, error) {
	authInfo := AuthInfo{
		Token: token,
	}

	// Extract client_id with fallback chain
	authInfo.ClientID = v.extractClientID(jwtToken)

	// Extract scopes
	authInfo.Scopes = v.extractScopes(jwtToken)

	// Extract expiration time
	if exp := jwtToken.Expiration(); !exp.IsZero() {
		expiresAt := exp.Unix()
		authInfo.ExpiresAt = &expiresAt
	}

	// Extract resource information
	authInfo.Resource = v.extractResource(jwtToken)

	// Extract custom fields to Extra
	authInfo.Extra = v.extractExtraClaims(jwtToken)

	// Validate required fields
	if authInfo.ClientID == "" {
		return AuthInfo{}, errors.New("token does not contain valid client_id")
	}

	return authInfo, nil
}

// extractClientID extracts client ID with fallback chain
func (v *JWKVerifier) extractClientID(jwtToken jwt.Token) string {
	// Try client_id first
	if clientID, ok := jwtToken.Get("client_id"); ok {
		if clientIDStr, ok := clientID.(string); ok {
			return clientIDStr
		}
	}

	// Try aud (audience) as fallback
	if aud := jwtToken.Audience(); len(aud) > 0 {
		return aud[0]
	}

	// Try sub (subject) as last resort
	if sub := jwtToken.Subject(); sub != "" {
		return sub
	}

	return ""
}

// extractScopes extracts scopes from various claim formats
func (v *JWKVerifier) extractScopes(jwtToken jwt.Token) []string {
	// Try "scope" field first (OAuth 2.1 standard)
	if scopesClaim, ok := jwtToken.Get("scope"); ok {
		switch scopes := scopesClaim.(type) {
		case string:
			return v.splitScopes(scopes)
		case []interface{}:
			return v.convertInterfaceArrayToStrings(scopes)
		case []string:
			return scopes
		}
	}

	// Try "scopes" field as alternative
	if scopesClaim, ok := jwtToken.Get("scopes"); ok {
		if scopesArray, ok := scopesClaim.([]interface{}); ok {
			return v.convertInterfaceArrayToStrings(scopesArray)
		}
	}

	return []string{}
}

// extractResource extracts resource information
func (v *JWKVerifier) extractResource(jwtToken jwt.Token) *url.URL {
	// Try "resource" field first
	if resourceClaim, ok := jwtToken.Get("resource"); ok {
		if resourceStr, ok := resourceClaim.(string); ok {
			if resourceURL, err := url.Parse(resourceStr); err == nil {
				return resourceURL
			}
		}
	}

	// Try second audience entry as resource (RFC 8707)
	if audienceClaim, ok := jwtToken.Get("aud"); ok {
		if audArray, ok := audienceClaim.([]interface{}); ok && len(audArray) > 1 {
			if resourceStr, ok := audArray[1].(string); ok {
				if resourceURL, err := url.Parse(resourceStr); err == nil {
					return resourceURL
				}
			}
		}
	}

	return nil
}

// extractExtraClaims extracts custom claims to Extra map
func (v *JWKVerifier) extractExtraClaims(jwtToken jwt.Token) map[string]interface{} {
	extra := make(map[string]interface{})

	// Standard JWT claims that should not be included in Extra
	standardClaims := map[string]bool{
		"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true,
		"iat": true, "jti": true, "client_id": true, "scope": true,
		"scopes": true, "resource": true, "kid": true,
	}

	// Extract all claims
	claimsMap, err := jwtToken.AsMap(context.Background())
	if err != nil {
		return extra
	}

	// Filter out standard claims
	for key, value := range claimsMap {
		if !standardClaims[key] {
			extra[key] = value
		}
	}

	return extra
}

// convertInterfaceArrayToStrings converts []interface{} to []string
func (v *JWKVerifier) convertInterfaceArrayToStrings(arr []interface{}) []string {
	strs := make([]string, 0, len(arr))
	for _, item := range arr {
		if str, ok := item.(string); ok {
			strs = append(strs, str)
		}
	}
	return strs
}

// splitScopes splits scope string by spaces, handling multiple consecutive spaces.
func (v *JWKVerifier) splitScopes(scopeStr string) []string {
	if scopeStr == "" {
		return []string{}
	}
	// Use strings.Fields to handle multiple spaces and trim
	return strings.Fields(scopeStr)
}

// LoadLocalKey loads a JWK key for local verification.
func (v *JWKVerifier) LoadLocalKey(key jwk.Key) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.localKeys.AddKey(key)
}

// LoadLocalKeyFromBytes loads a key from raw bytes (PEM, etc.)
func (v *JWKVerifier) LoadLocalKeyFromBytes(keyData []byte, keyID string) error {
	key, err := jwk.ParseKey(keyData)
	if err != nil {
		return fmt.Errorf("failed to parse key: %v", err)
	}

	// Set key ID if provided
	if keyID != "" {
		if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
			return fmt.Errorf("failed to set key ID: %v", err)
		}
	}

	return v.LoadLocalKey(key)
}

// GetLocalKeys returns information about currently loaded local keys.
func (v *JWKVerifier) GetLocalKeys() []map[string]interface{} {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var keys []map[string]interface{}
	iter := v.localKeys.Keys(context.Background())
	for iter.Next(context.Background()) {
		pair := iter.Pair()
		key := pair.Value.(jwk.Key)

		keyInfo := map[string]interface{}{
			"kty": key.KeyType().String(),
			"use": "sig", // Default for signature verification
		}

		if keyID := key.KeyID(); keyID != "" {
			keyInfo["kid"] = keyID
		}

		keys = append(keys, keyInfo)
	}

	return keys
}

// SetJWKSURL updates the JWKS URL (useful for configuration changes).
func (v *JWKVerifier) SetJWKSURL(url string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.jwksURL = url
}

// ClearLocalKeys clears all locally cached keys.
func (v *JWKVerifier) ClearLocalKeys() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.localKeys = jwk.NewSet()
}

// GetCacheStats returns cache statistics for monitoring
func (v *JWKVerifier) GetCacheStats() map[string]interface{} {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return map[string]interface{}{
		"local_keys_count": v.localKeys.Len(),
		"jwks_url":         v.jwksURL,
		"remote_enabled":   v.remoteEnabled,
	}
}

// NewJWKVerifierFunc returns a function compatible with ProxyOptions.VerifyAccessToken.
// 注意：如果接口需要返回指针，请使用 VerifyAccessTokenPtr
func NewJWKVerifierFunc(jwksURL string, remoteEnabled bool) func(token string) (AuthInfo, error) {
	verifier := NewJWKVerifier(jwksURL, remoteEnabled)
	return verifier.VerifyAccessToken
}
