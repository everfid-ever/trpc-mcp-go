// Tencent is pleased to support the open source community by making trpc-mcp-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-mcp-go is licensed under the Apache License Version 2.0.

package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	oauthErrors "trpc.group/trpc-go/trpc-mcp-go/internal/errors"
)

// Standard JWT claims that should not be included in Extra
var standardClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "iat": true,
	"jti": true, "client_id": true, "scope": true, "kid": true,
}

// TokenVerifierInterface defines the interface for verifying tokens.
type TokenVerifierInterface interface {
	VerifyAccessToken(ctx context.Context, token string) (AuthInfo, error)
}

// LocalJWKSConfig represents configuration for local JWKS.
type LocalJWKSConfig struct {
	JWKS string // Local JWKS JSON string
	File string // Local JWKS file path
}

// RemoteJWKSConfig represents configuration for remote JWKS.
type RemoteJWKSConfig struct {
	URLs            []string          // Remote JWKS URLs
	IssuerToURL     map[string]string // Mapping from issuer (iss) to remote JWKS URL
	RefreshInterval time.Duration     // Refresh interval for cache
}

// TokenVerifierConfig represents the overall configuration for TokenVerifier.
type TokenVerifierConfig struct {
	Local  *LocalJWKSConfig  // Local JWKS config
	Remote *RemoteJWKSConfig // Remote JWKS config
}

// TokenVerifier verifies JWT tokens using JWKS (local or remote)
type TokenVerifier struct {
	localKeySet jwk.Set           // Local JWKS key set
	cache       *jwk.Cache        // Cache for remote JWKS
	issuerToURL map[string]string // Mapping from issuer to remote JWKS URL
	isRemote    bool              // Whether remote mode is enabled
}

// TokenVerifierFunc is a function adapter to implement TokenVerifierInterface
type TokenVerifierFunc func(ctx context.Context, token string) (AuthInfo, error)

func (f TokenVerifierFunc) VerifyAccessToken(ctx context.Context, token string) (AuthInfo, error) {
	return f(ctx, token)
}

// NewLocalTokenVerifier creates a TokenVerifier that only uses local JWKS
func NewLocalTokenVerifier(ctx context.Context, cfg LocalJWKSConfig) (*TokenVerifier, error) {
	verifier := &TokenVerifier{}

	defaultSet := jwk.NewSet()

	// Load JWKS string if provided
	if cfg.JWKS != "" {
		set, err := jwk.ParseString(cfg.JWKS)
		if err != nil {
			return nil, fmt.Errorf("failed to parse local JWKS: %w", err)
		}

		// Iterate through keys and add them to the default set
		iter := set.Keys(ctx)
		for iter.Next(ctx) {
			pair := iter.Pair()
			key := pair.Value.(jwk.Key)
			if err := defaultSet.AddKey(key); err != nil {
				return nil, fmt.Errorf("failed to add key to set: %w", err)
			}
		}
	}

	// Load JWKS file if provided
	if cfg.File != "" {
		set, err := jwk.ReadFile(cfg.File)
		if err != nil {
			return nil, fmt.Errorf("failed to parse local JWKS file: %w", err)
		}

		// Iterate through keys and add them to the default set
		iter := set.Keys(ctx)
		for iter.Next(ctx) {
			pair := iter.Pair()
			key := pair.Value.(jwk.Key)
			if err := defaultSet.AddKey(key); err != nil {
				return nil, fmt.Errorf("failed to add key to set: %w", err)
			}
		}
	}

	// Ensure at least one key was loaded
	if defaultSet.Len() == 0 {
		return nil, fmt.Errorf("must provide JWKS or File")
	}

	verifier.localKeySet = defaultSet
	return verifier, nil
}

// NewRemoteTokenVerifier creates a TokenVerifier that only uses remote JWKS
func NewRemoteTokenVerifier(ctx context.Context, cfg RemoteJWKSConfig) (*TokenVerifier, error) {
	if len(cfg.URLs) == 0 {
		return nil, fmt.Errorf("must provide at least one RemoteURL")
	}

	refreshInterval := cfg.RefreshInterval
	if refreshInterval == 0 {
		// Default refresh interval: 1 hour
		refreshInterval = 60 * time.Minute
	}
	if refreshInterval < 15*time.Minute {
		refreshInterval = 15 * time.Minute
	}

	cache := jwk.NewCache(ctx)

	// Register all remote JWKS URLs
	for _, url_ := range cfg.URLs {
		if err := cache.Register(url_, jwk.WithRefreshInterval(refreshInterval)); err != nil {
			return nil, fmt.Errorf("failed to register remote JWKS %s: %w", url_, err)
		}
	}

	return &TokenVerifier{
		cache:       cache,
		issuerToURL: cfg.IssuerToURL,
		isRemote:    true,
	}, nil
}

// NewTokenVerifier creates a TokenVerifier using both local and remote configurations if provided
func NewTokenVerifier(ctx context.Context, cfg TokenVerifierConfig) (*TokenVerifier, error) {
	var verifier *TokenVerifier
	var err error

	// Prefer remote verifier if configured
	if cfg.Remote != nil && len(cfg.Remote.URLs) > 0 {
		verifier, err = NewRemoteTokenVerifier(ctx, *cfg.Remote)
		if err != nil {
			return nil, err
		}
	}

	// Also load local verifier if configured
	if cfg.Local != nil && (cfg.Local.JWKS != "" || cfg.Local.File != "") {
		localVerifier, err := NewLocalTokenVerifier(ctx, *cfg.Local)
		if err != nil {
			return nil, err
		}

		if verifier != nil {
			verifier.localKeySet = localVerifier.localKeySet
		} else {
			verifier = localVerifier
		}
	}

	if verifier == nil {
		return nil, errors.New("must provide either Local or Remote configuration")
	}

	return verifier, nil
}

// VerifyAccessToken verifies a JWT token and returns AuthInfo or error
func (v *TokenVerifier) VerifyAccessToken(ctx context.Context, tokenStr string) (AuthInfo, error) {
	// Parse token without verification to get headers and claims
	msg, err := jws.ParseString(tokenStr)
	if err != nil {
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrServerError, fmt.Sprintf("failed to parse token: %v", err.Error()), "")
	}

	// Get the first signature (assuming single signature)
	if len(msg.Signatures()) == 0 {
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "no signatures found in token", "")
	}

	headers := msg.Signatures()[0].ProtectedHeaders()

	// Extract key ID (kid)
	kidInterface, ok := headers.Get("kid")
	if !ok {
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "missing kid in token header", "")
	}

	kid, ok := kidInterface.(string)
	if !ok || kid == "" {
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "invalid kid in token header", "")
	}

	// Parse payload to get issuer
	payload := msg.Payload()
	unverifiedToken, err := jwt.Parse(payload, jwt.WithVerify(false))
	if err != nil {
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrServerError, fmt.Sprintf("failed to parse token payload: %v", err.Error()), "")
	}

	// Extract issuer (iss)
	iss := unverifiedToken.Issuer()
	if iss == "" {
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "missing iss claim in token", "")
	}

	// Get target key set from local or remote
	keySet, err := v.getTargetKeySet(ctx, iss, kid)
	if err != nil {
		return AuthInfo{}, err
	}

	// Parse and validate token with key set
	token, err := jwt.ParseString(tokenStr,
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(30*time.Second),
	)
	if err != nil || token == nil {
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "failed to verify token", "")
	}

	// Validate required claims per RFC 9068
	requiredClaims := []string{"exp", "aud", "sub", "client_id", "iat", "jti", "scope"}
	for _, claim := range requiredClaims {
		if _, ok := token.Get(claim); !ok {
			return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, fmt.Sprintf("missing required claim: %s", claim), "")
		}
	}

	// Ensure subject is not empty
	if sub := token.Subject(); sub == "" {
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "missing required 'sub' claim", "")
	}

	authInfo, err := v.convertJWTToAuthInfo(token, tokenStr)
	if err != nil {
		return AuthInfo{}, err
	}
	return authInfo, nil
}

// getTargetKeySet selects the appropriate JWKS based on issuer and kid.
func (v *TokenVerifier) getTargetKeySet(ctx context.Context, iss, kid string) (jwk.Set, error) {
	// First, try local JWKS
	if v.localKeySet != nil {
		if _, ok := v.localKeySet.LookupKeyID(kid); ok {
			return v.localKeySet, nil
		}
	}

	// If remote mode, try remote JWKS
	if v.isRemote {
		if url_, ok := v.issuerToURL[iss]; ok {
			keySet, err := v.cache.Refresh(ctx, url_)
			if err != nil {
				return nil, fmt.Errorf("failed to refresh remote JWKS for issuer %s: %w", iss, err)
			}
			return keySet, nil
		}
		return nil, fmt.Errorf("no remote JWKS URL found for issuer %s", iss)
	}

	return nil, fmt.Errorf("no JWKS found for issuer %s", iss)
}

// convertJWTToAuthInfo converts jwt.Token to AuthInfo structure
func (v *TokenVerifier) convertJWTToAuthInfo(token jwt.Token, tokenStr string) (AuthInfo, error) {
	authInfo := AuthInfo{Token: tokenStr}

	// Extract exp claim
	if exp := token.Expiration(); !exp.IsZero() {
		ts := exp.Unix()
		authInfo.ExpiresAt = &ts
	} else {
		// Should not happen due to required claims, but fallback
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "missing exp claim", "")
	}

	// Extract OAuth claims
	var err error
	if authInfo.ClientID, err = extractClientID(token); err != nil {
		return AuthInfo{}, err
	}
	if authInfo.Resource, err = extractResource(token); err != nil {
		return AuthInfo{}, err
	}
	if authInfo.Scopes, err = extractScopes(token); err != nil {
		return AuthInfo{}, err
	}

	// Extract extra custom claims
	authInfo.Extra = extractExtra(token)
	return authInfo, nil
}

// extractClientID extracts client ID from token
func extractClientID(token jwt.Token) (string, error) {
	clientIDInterface, ok := token.Get("client_id")
	if !ok {
		return "", errors.New("token does not contain client_id claim")
	}

	clientID, ok := clientIDInterface.(string)
	if !ok || clientID == "" {
		return "", errors.New("token does not contain valid client_id")
	}
	return clientID, nil
}

// extractScopes extracts scope claims in different formats (string, array)
func extractScopes(token jwt.Token) ([]string, error) {
	tempScopes, ok := token.Get("scope")
	if !ok {
		return nil, errors.New("token does not contain scope claim")
	}

	switch s := tempScopes.(type) {
	case string:
		if s == "" {
			return nil, errors.New("token does not contain valid scope")
		}
		return strings.Split(s, " "), nil
	case []string:
		if len(s) == 0 {
			return nil, errors.New("token does not contain valid scope")
		}
		return s, nil
	case []interface{}:
		// Handle JSON-unmarshaled []interface{}
		if len(s) == 0 {
			return nil, errors.New("token does not contain valid scope")
		}
		var scopes []string
		for _, v := range s {
			if str, ok := v.(string); ok {
				scopes = append(scopes, str)
			}
		}
		if len(scopes) == 0 {
			return nil, errors.New("token does not contain valid scope")
		}
		return scopes, nil
	default:
		return nil, errors.New("token scope claim has invalid type")
	}
}

// extractResource extracts resource (audience) claim and validates it as a URL
func extractResource(token jwt.Token) (*url.URL, error) {
	audInterface, ok := token.Get("aud")
	if !ok {
		return nil, fmt.Errorf("missing required 'aud' claim")
	}

	var aud []string
	switch a := audInterface.(type) {
	case string:
		aud = []string{a}
	case []string:
		aud = a
	case []interface{}:
		for _, v := range a {
			if str, ok := v.(string); ok {
				aud = append(aud, str)
			}
		}
	default:
		return nil, fmt.Errorf("invalid aud claim type")
	}

	if len(aud) == 0 {
		return nil, fmt.Errorf("missing required 'aud' claim")
	}

	// Use first audience as resource
	resourceStr := aud[0]
	resourceURL, err := url.Parse(resourceStr)
	if err != nil {
		return nil, fmt.Errorf("invalid resource URL: %s", resourceStr)
	}

	if resourceURL == nil {
		return nil, fmt.Errorf("invalid resource URL: %s", resourceStr)
	}

	// Ensure scheme and host are present
	if resourceURL.Scheme == "" || resourceURL.Host == "" {
		return nil, fmt.Errorf("invalid resource URL: %s", resourceStr)
	}

	resourceURL.Fragment = "" // Remove fragment per RFC 8707
	return resourceURL, nil
}

// extractExtra extracts non-standard claims into a map
func extractExtra(token jwt.Token) map[string]interface{} {
	extra := make(map[string]interface{})

	// Get private claims map - in JWX v2, we need to use PrivateClaims()
	privateClaims := token.PrivateClaims()
	if privateClaims == nil {
		return nil
	}

	for key, value := range privateClaims {
		if standardClaims[key] {
			// Skip standard claims
			continue
		}
		extra[key] = value
	}

	if len(extra) == 0 {
		// Return nil for empty map (omitempty)
		return nil
	}

	return extra
}

// AddIssuerURL dynamically adds or updates an issuer → JWKS URL mapping
func (v *TokenVerifier) AddIssuerURL(ctx context.Context, iss, url string, refreshInterval time.Duration) error {
	if !v.isRemote {
		return errors.New("cannot add issuer URL: remote JWKS support is disabled")
	}
	if url == "" {
		return errors.New("JWKS URL cannot be empty")
	}
	if !strings.HasPrefix(url, "https://") {
		return errors.New("JWKS URL must use HTTPS")
	}

	// Register JWKS URL in cache
	if err := v.cache.Register(url, jwk.WithRefreshInterval(refreshInterval)); err != nil {
		return fmt.Errorf("failed to register JWKS URL %s: %w", url, err)
	}

	if v.issuerToURL == nil {
		v.issuerToURL = make(map[string]string)
	}
	v.issuerToURL[iss] = url
	return nil
}

// ClearLocalKeys clears all locally cached keys.
func (v *TokenVerifier) ClearLocalKeys() {
	if v.localKeySet != nil {
		// Create a new empty set to replace the current one
		v.localKeySet = jwk.NewSet()
	}
}
