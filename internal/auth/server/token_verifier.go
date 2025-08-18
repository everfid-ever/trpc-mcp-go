package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	oautherrors "trpc.group/trpc-go/trpc-mcp-go/internal/errors"
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
	// Try to parse with local keys
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

		return parsedToken, nil
	}

	return nil, errors.New("no valid key found for verification")
}

// verifyTokenInternal performs comprehensive OAuth 2.1 token verification for both access and refresh tokens.
func (v *JWKVerifier) verifyTokenInternal(token string, expectedTokenType TokenType) (AuthInfo, error) {
	ctx := context.Background()

	//  Verify JWT signature
	jwtToken, err := v.VerifyToken(ctx, token, expectedTokenType)
	if err != nil {
		return AuthInfo{}, oautherrors.NewOAuthError(oautherrors.ErrInvalidToken,
			fmt.Sprintf("token signature verification failed: %v", err), "")
	}

	// 2. Validate OAuth 2.1 Claims
	if err := v.validateOAuth21Claims(jwtToken, expectedTokenType); err != nil {
		return AuthInfo{}, oautherrors.NewOAuthError(oautherrors.ErrInvalidToken, err.Error(), "")
	}

	// 3. Convert to AuthInfo
	return v.convertJWTToAuthInfo(jwtToken, token, expectedTokenType)
}

// validateOAuth21Claims validates OAuth 2.1 standard JWT claims according to RFC 6749, RFC 7519, and RFC 9068.
func (v *JWKVerifier) validateOAuth21Claims(jwtToken jwt.Token, tokenType TokenType) error {
	now := time.Now()

	// Verification expiration time
	if exp := jwtToken.Expiration(); exp.IsZero() {
		return fmt.Errorf("missing required 'exp' claim")
	} else if now.After(exp) {
		return fmt.Errorf("token expired at %v", exp)
	}

	// Verification effective time
	if nbf := jwtToken.NotBefore(); !nbf.IsZero() && now.Before(nbf) {
		return fmt.Errorf("token not valid until %v", nbf)
	}

	// Verify the rationality of issuance time
	if iat := jwtToken.IssuedAt(); !iat.IsZero() {
		if now.Before(iat) {
			return fmt.Errorf("token issued in the future: %v", iat)
		}
		// Check token age
		maxAge := time.Hour * 24
		if now.Sub(iat) > maxAge {
			return fmt.Errorf("token too old: issued %v ago", now.Sub(iat))
		}
	}

	// Verify subject
	if jwtToken.Subject() == "" {
		return fmt.Errorf("missing required 'sub' claim")
	}

	// Verify issuer
	if jwtToken.Issuer() == "" {
		return fmt.Errorf("missing required 'iss' claim")
	}

	// Verify audience
	if len(jwtToken.Audience()) == 0 {
		return fmt.Errorf("missing required 'aud' claim")
	}

	// Verify token type specific claims
	return v.validateTokenTypeSpecificClaims(jwtToken, tokenType)
}

// validateTokenTypeSpecificClaims validates token type specific claims according to OAuth 2.1 and RFC 9068 standards.
func (v *JWKVerifier) validateTokenTypeSpecificClaims(jwtToken jwt.Token, tokenType TokenType) error {
	// 检查 typ header claim
	if typ, ok := jwtToken.Get("typ"); ok {
		if typStr, ok := typ.(string); ok {
			expectedTyp := "at+jwt" // RFC 9068: JWT Profile for OAuth 2.0 Access Tokens
			if tokenType == RefreshToken {
				expectedTyp = "rt+jwt" // Refresh token type
			}
			if !strings.EqualFold(typStr, expectedTyp) {
				return fmt.Errorf("invalid token type in 'typ' claim: expected %s, got %s", expectedTyp, typStr)
			}
		}
	}

	// Check token_use claim (used by some implementations)
	if tokenUse, ok := jwtToken.Get("token_use"); ok {
		if tokenUseStr, ok := tokenUse.(string); ok {
			expectedUse := string(tokenType)
			if tokenUseStr != expectedUse {
				return fmt.Errorf("invalid token_use: expected %s, got %s", expectedUse, tokenUseStr)
			}
		}
	}

	return nil
}

// VerifyAccessToken verifies an access token and returns AuthInfo directly.
func (v *JWKVerifier) VerifyAccessToken(token string) (*AuthInfo, error) {
	authInfo, err := v.verifyTokenInternal(token, AccessToken)
	if err != nil {
		return nil, err
	}
	return &authInfo, nil
}

// VerifyRefreshToken verifies a refresh token and returns AuthInfo.
func (v *JWKVerifier) VerifyRefreshToken(token string) (*AuthInfo, error) {
	authInfo, err := v.verifyTokenInternal(token, RefreshToken)
	if err != nil {
		return nil, err
	}
	return &authInfo, nil
}

// convertJWTToAuthInfo converts jwt.Token to AuthInfo structure.
func (v *JWKVerifier) convertJWTToAuthInfo(jwtToken jwt.Token, token string, tokenType TokenType) (AuthInfo, error) {
	authInfo := AuthInfo{
		Token:     token,
		TokenType: string(tokenType),
	}

	// Extract Basic OAuth fields with fallback chain
	authInfo.ClientID = v.extractClientID(jwtToken)
	authInfo.Scopes = v.extractScopes(jwtToken)
	authInfo.Resource = v.extractResource(jwtToken)
	authInfo.Extra = v.extractExtraClaims(jwtToken)

	// OAuth 2.1 Standard Fields
	authInfo.Subject = jwtToken.Subject()
	authInfo.Issuer = jwtToken.Issuer()
	authInfo.Audience = jwtToken.Audience()

	// Extract expiration time
	if exp := jwtToken.Expiration(); !exp.IsZero() {
		expiresAt := exp.Unix()
		authInfo.ExpiresAt = &expiresAt
	}

	if iat := jwtToken.IssuedAt(); !iat.IsZero() {
		issuedAt := iat.Unix()
		authInfo.IssuedAt = &issuedAt
	}

	if nbf := jwtToken.NotBefore(); !nbf.IsZero() {
		notBefore := nbf.Unix()
		authInfo.NotBefore = &notBefore
	}

	// Validate required fields
	if authInfo.ClientID == "" {
		return AuthInfo{}, errors.New("token does not contain valid client_id")
	}

	if authInfo.Subject == "" {
		return AuthInfo{}, errors.New("token does not contain valid subject")
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
	if v.localKeys == nil {
		v.localKeys = jwk.NewSet()
	}
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
	v.mu.Lock()
	defer v.mu.Unlock()

	var keys []map[string]interface{}

	if v.localKeys == nil {
		return keys
	}

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
func NewJWKVerifierFunc(jwksURL string, remoteEnabled bool) func(token string) (*AuthInfo, error) {
	verifier := NewJWKVerifier(jwksURL, remoteEnabled)
	return verifier.VerifyAccessToken
}
