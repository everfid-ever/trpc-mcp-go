package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper functions

// generateRSAKey generates a new RSA key pair for testing
func generateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// createTestJWK creates a test JWK from RSA key
func createTestJWK(privateKey *rsa.PrivateKey, keyID string) (jwk.Key, error) {
	// Import the public key part only
	publicKey := &privateKey.PublicKey
	key, err := jwk.Import(publicKey)
	if err != nil {
		return nil, err
	}

	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, err
	}

	if err := key.Set(jwk.AlgorithmKey, "RS256"); err != nil {
		return nil, err
	}

	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, err
	}

	return key, nil
}

// createTestToken creates a test JWT token
func createTestToken(privateKey *rsa.PrivateKey, keyID string, claims map[string]interface{}) (string, error) {
	key, err := jwk.Import(privateKey)
	if err != nil {
		return "", err
	}

	if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
		return "", err
	}

	now := time.Now()
	token := jwt.New()

	// Set standard claims
	token.Set(jwt.IssuerKey, "https://example.com")
	token.Set(jwt.SubjectKey, "user123")
	token.Set(jwt.AudienceKey, []string{"https://api.example.com"})
	token.Set(jwt.ExpirationKey, now.Add(time.Hour))
	token.Set(jwt.IssuedAtKey, now)
	token.Set(jwt.JwtIDKey, "jti-123")
	token.Set("client_id", "test-client")
	token.Set("scope", "read write")
	token.Set("kid", keyID)

	// Set custom claims
	for k, v := range claims {
		token.Set(k, v)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		return "", err
	}

	return string(signed), nil
}

// createTestJWKS creates a test JWKS JSON string
func createTestJWKS(keys ...jwk.Key) string {
	set := jwk.NewSet()
	for _, key := range keys {
		set.AddKey(key)
	}

	buf, _ := json.Marshal(set)
	return string(buf)
}

// Test fixtures
func setupTestKeys(t *testing.T) (*rsa.PrivateKey, jwk.Key, string) {
	privateKey, err := generateRSAKey()
	require.NoError(t, err)

	publicKey, err := createTestJWK(privateKey, "test-key-1")
	require.NoError(t, err)

	jwksJSON := createTestJWKS(publicKey)

	return privateKey, publicKey, jwksJSON
}

func TestTokenVerifierFunc_VerifyAccessToken(t *testing.T) {
	ctx := context.Background()

	// 定义一个假的 verifier 函数
	fn := TokenVerifierFunc(func(ctx context.Context, token string) (AuthInfo, error) {
		if token == "valid" {
			return AuthInfo{Token: token, ClientID: "test-client"}, nil
		}
		return AuthInfo{}, errors.New("invalid token")
	})

	// 成功路径
	authInfo, err := fn.VerifyAccessToken(ctx, "valid")
	assert.NoError(t, err)
	assert.Equal(t, "valid", authInfo.Token)
	assert.Equal(t, "test-client", authInfo.ClientID)

	// 失败路径
	authInfo, err = fn.VerifyAccessToken(ctx, "invalid")
	assert.Error(t, err)
	assert.Empty(t, authInfo.Token)
}

// Tests for NewLocalTokenVerifier

func TestNewLocalTokenVerifier_WithJWKSString(t *testing.T) {
	ctx := context.Background()
	_, _, jwksJSON := setupTestKeys(t)

	cfg := LocalJWKSConfig{
		JWKS: jwksJSON,
	}

	verifier, err := NewLocalTokenVerifier(ctx, cfg)
	assert.NoError(t, err)
	assert.NotNil(t, verifier)
	assert.NotNil(t, verifier.localKeySet)
	assert.False(t, verifier.isRemote)
	assert.Equal(t, 1, verifier.localKeySet.Len())
}

func TestNewLocalTokenVerifier_WithFile(t *testing.T) {
	ctx := context.Background()
	_, _, jwksJSON := setupTestKeys(t)

	// Create temporary file
	tmpFile, err := os.CreateTemp("", "jwks-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(jwksJSON)
	require.NoError(t, err)
	tmpFile.Close()

	cfg := LocalJWKSConfig{
		File: tmpFile.Name(),
	}

	verifier, err := NewLocalTokenVerifier(ctx, cfg)
	assert.NoError(t, err)
	assert.NotNil(t, verifier)
	assert.Equal(t, 1, verifier.localKeySet.Len())
}

func TestNewLocalTokenVerifier_WithBothJWKSAndFile(t *testing.T) {
	ctx := context.Background()

	// Create two different keys
	_, _, jwksJSON1 := setupTestKeys(t)

	privateKey2, err := generateRSAKey()
	require.NoError(t, err)
	publicKey2, err := createTestJWK(privateKey2, "test-key-2")
	require.NoError(t, err)
	jwksJSON2 := createTestJWKS(publicKey2)

	// Create temporary file with second key
	tmpFile, err := os.CreateTemp("", "jwks-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(jwksJSON2)
	require.NoError(t, err)
	tmpFile.Close()

	cfg := LocalJWKSConfig{
		JWKS: jwksJSON1,
		File: tmpFile.Name(),
	}

	verifier, err := NewLocalTokenVerifier(ctx, cfg)
	assert.NoError(t, err)
	assert.NotNil(t, verifier)
	assert.Equal(t, 2, verifier.localKeySet.Len()) // Should have both keys
}

func TestNewLocalTokenVerifier_EmptyConfig(t *testing.T) {
	ctx := context.Background()
	cfg := LocalJWKSConfig{}

	verifier, err := NewLocalTokenVerifier(ctx, cfg)
	assert.Error(t, err)
	assert.Nil(t, verifier)
	assert.Contains(t, err.Error(), "must provide JWKS or File")
}

func TestNewLocalTokenVerifier_InvalidJWKS(t *testing.T) {
	ctx := context.Background()
	cfg := LocalJWKSConfig{
		JWKS: "invalid-json",
	}

	verifier, err := NewLocalTokenVerifier(ctx, cfg)
	assert.Error(t, err)
	assert.Nil(t, verifier)
	assert.Contains(t, err.Error(), "failed to parse local JWKS")
}

// Tests for NewRemoteTokenVerifier

func TestNewRemoteTokenVerifier_Success(t *testing.T) {
	ctx := context.Background()
	_, _, jwksJSON := setupTestKeys(t)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksJSON))
	}))
	defer server.Close()

	cfg := RemoteJWKSConfig{
		URLs: []string{server.URL},
		IssuerToURL: map[string]string{
			"https://example.com": server.URL,
		},
		RefreshInterval: time.Minute,
	}

	verifier, err := NewRemoteTokenVerifier(ctx, cfg)
	assert.NoError(t, err)
	assert.NotNil(t, verifier)
	assert.True(t, verifier.isRemote)
	assert.NotNil(t, verifier.cache)
	assert.Equal(t, server.URL, verifier.issuerToURL["https://example.com"])
}

func TestNewRemoteTokenVerifier_EmptyURLs(t *testing.T) {
	ctx := context.Background()
	cfg := RemoteJWKSConfig{}

	verifier, err := NewRemoteTokenVerifier(ctx, cfg)
	assert.Error(t, err)
	assert.Nil(t, verifier)
	assert.Contains(t, err.Error(), "must provide at least one RemoteURL")
}

func TestNewRemoteTokenVerifier_DefaultRefreshInterval(t *testing.T) {
	ctx := context.Background()
	_, _, jwksJSON := setupTestKeys(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksJSON))
	}))
	defer server.Close()

	cfg := RemoteJWKSConfig{
		URLs: []string{server.URL},
		// RefreshInterval is 0, should use default (60 minutes)
	}

	verifier, err := NewRemoteTokenVerifier(ctx, cfg)
	assert.NoError(t, err)
	assert.NotNil(t, verifier)
}

// Tests for NewTokenVerifier

func TestNewTokenVerifier_LocalOnly(t *testing.T) {
	ctx := context.Background()
	_, _, jwksJSON := setupTestKeys(t)

	cfg := TokenVerifierConfig{
		Local: &LocalJWKSConfig{
			JWKS: jwksJSON,
		},
	}

	verifier, err := NewTokenVerifier(ctx, cfg)
	assert.NoError(t, err)
	assert.NotNil(t, verifier)
	assert.NotNil(t, verifier.localKeySet)
	assert.False(t, verifier.isRemote)
}

func TestNewTokenVerifier_RemoteOnly(t *testing.T) {
	ctx := context.Background()
	_, _, jwksJSON := setupTestKeys(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksJSON))
	}))
	defer server.Close()

	cfg := TokenVerifierConfig{
		Remote: &RemoteJWKSConfig{
			URLs: []string{server.URL},
		},
	}

	verifier, err := NewTokenVerifier(ctx, cfg)
	assert.NoError(t, err)
	assert.NotNil(t, verifier)
	assert.True(t, verifier.isRemote)
	assert.NotNil(t, verifier.cache)
}

func TestNewTokenVerifier_Combined(t *testing.T) {
	ctx := context.Background()
	_, _, jwksJSON := setupTestKeys(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksJSON))
	}))
	defer server.Close()

	cfg := TokenVerifierConfig{
		Local: &LocalJWKSConfig{
			JWKS: jwksJSON,
		},
		Remote: &RemoteJWKSConfig{
			URLs: []string{server.URL},
		},
	}

	verifier, err := NewTokenVerifier(ctx, cfg)
	assert.NoError(t, err)
	assert.NotNil(t, verifier)
	assert.True(t, verifier.isRemote)
	assert.NotNil(t, verifier.cache)
	assert.NotNil(t, verifier.localKeySet)
}

func TestNewTokenVerifier_EmptyConfig(t *testing.T) {
	ctx := context.Background()
	cfg := TokenVerifierConfig{}

	verifier, err := NewTokenVerifier(ctx, cfg)
	assert.Error(t, err)
	assert.Nil(t, verifier)
	assert.Contains(t, err.Error(), "must provide either Local or Remote configuration")
}

// Tests for VerifyAccessToken

func TestVerifyAccessToken_LocalSuccess(t *testing.T) {
	ctx := context.Background()
	privateKey, _, jwksJSON := setupTestKeys(t)

	cfg := LocalJWKSConfig{
		JWKS: jwksJSON,
	}

	verifier, err := NewLocalTokenVerifier(ctx, cfg)
	require.NoError(t, err)

	// Create valid token
	tokenStr, err := createTestToken(privateKey, "test-key-1", map[string]interface{}{
		"custom_claim": "custom_value",
	})
	require.NoError(t, err)

	authInfo, err := verifier.VerifyAccessToken(ctx, tokenStr)
	assert.NoError(t, err)
	assert.Equal(t, tokenStr, authInfo.Token)
	assert.Equal(t, "test-client", authInfo.ClientID)
	assert.Equal(t, []string{"read", "write"}, authInfo.Scopes)
	assert.NotNil(t, authInfo.Resource)
	assert.Equal(t, "https://api.example.com", authInfo.Resource.String())
	assert.Equal(t, "custom_value", authInfo.Extra["custom_claim"])
}

func TestVerifyAccessToken_InvalidToken(t *testing.T) {
	ctx := context.Background()
	_, _, jwksJSON := setupTestKeys(t)

	cfg := LocalJWKSConfig{
		JWKS: jwksJSON,
	}

	verifier, err := NewLocalTokenVerifier(ctx, cfg)
	require.NoError(t, err)

	authInfo, err := verifier.VerifyAccessToken(ctx, "invalid-token")
	assert.Error(t, err)
	assert.Empty(t, authInfo)
}

func TestVerifyAccessToken_ExpiredToken(t *testing.T) {
	ctx := context.Background()
	privateKey, _, jwksJSON := setupTestKeys(t)

	cfg := LocalJWKSConfig{
		JWKS: jwksJSON,
	}

	verifier, err := NewLocalTokenVerifier(ctx, cfg)
	require.NoError(t, err)

	// Create expired token
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	err = key.Set(jwk.KeyIDKey, "test-key-1")
	require.NoError(t, err)

	now := time.Now()
	token := jwt.New()

	token.Set(jwt.IssuerKey, "https://example.com")
	token.Set(jwt.SubjectKey, "user123")
	token.Set(jwt.AudienceKey, []string{"https://api.example.com"})
	token.Set(jwt.ExpirationKey, now.Add(-time.Hour)) // Expired 1 hour ago
	token.Set(jwt.IssuedAtKey, now.Add(-2*time.Hour))
	token.Set(jwt.JwtIDKey, "jti-123")
	token.Set("client_id", "test-client")
	token.Set("scope", "read write")
	token.Set("kid", "test-key-1")

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key))
	require.NoError(t, err)

	authInfo, err := verifier.VerifyAccessToken(ctx, string(signed))
	assert.Error(t, err)
	assert.Empty(t, authInfo)
}

func TestVerifyAccessToken_MissingRequiredClaims(t *testing.T) {
	ctx := context.Background()
	privateKey, _, jwksJSON := setupTestKeys(t)

	cfg := LocalJWKSConfig{
		JWKS: jwksJSON,
	}

	verifier, err := NewLocalTokenVerifier(ctx, cfg)
	require.NoError(t, err)

	// Create token missing required claims
	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	err = key.Set(jwk.KeyIDKey, "test-key-1")
	require.NoError(t, err)

	token := jwt.New()
	token.Set(jwt.IssuerKey, "https://example.com")
	// Missing other required claims
	token.Set("kid", "test-key-1")

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key))
	require.NoError(t, err)

	authInfo, err := verifier.VerifyAccessToken(ctx, string(signed))
	assert.Error(t, err)
	assert.Empty(t, authInfo)
}

func TestVerifyAccessToken_NoMatchingKey(t *testing.T) {
	ctx := context.Background()
	privateKey, _, jwksJSON := setupTestKeys(t)

	cfg := LocalJWKSConfig{
		JWKS: jwksJSON,
	}

	verifier, err := NewLocalTokenVerifier(ctx, cfg)
	require.NoError(t, err)

	// Create token with different key ID
	tokenStr, err := createTestToken(privateKey, "different-key-id", nil)
	require.NoError(t, err)

	authInfo, err := verifier.VerifyAccessToken(ctx, tokenStr)
	assert.Error(t, err)
	assert.Empty(t, authInfo)
}

// Tests for extractScopes

func TestExtractScopes_StringFormat(t *testing.T) {
	token := jwt.New()
	token.Set("scope", "read write admin")

	scopes, err := extractScopes(token)
	assert.NoError(t, err)
	assert.Equal(t, []string{"read", "write", "admin"}, scopes)
}

func TestExtractScopes_ArrayFormat(t *testing.T) {
	token := jwt.New()
	token.Set("scope", []string{"read", "write", "admin"})

	scopes, err := extractScopes(token)
	assert.NoError(t, err)
	assert.Equal(t, []string{"read", "write", "admin"}, scopes)
}

func TestExtractScopes_EmptyString(t *testing.T) {
	token := jwt.New()
	token.Set("scope", "")

	scopes, err := extractScopes(token)
	assert.Error(t, err)
	assert.Empty(t, scopes)
}

func TestExtractScopes_EmptyArray(t *testing.T) {
	token := jwt.New()
	token.Set("scope", []string{})

	scopes, err := extractScopes(token)
	assert.Error(t, err)
	assert.Empty(t, scopes)
}

// Tests for extractResource

func TestExtractResource_ValidURL(t *testing.T) {
	token := jwt.New()
	token.Set(jwt.AudienceKey, []string{"https://api.example.com/resource"})

	resource, err := extractResource(token)
	assert.NoError(t, err)
	assert.NotNil(t, resource)
	assert.Equal(t, "https://api.example.com/resource", resource.String())
}

func TestExtractResource_URLWithFragment(t *testing.T) {
	token := jwt.New()
	token.Set(jwt.AudienceKey, []string{"https://api.example.com/resource#fragment"})

	resource, err := extractResource(token)
	assert.NoError(t, err)
	assert.NotNil(t, resource)
	assert.Equal(t, "https://api.example.com/resource", resource.String()) // Fragment should be removed
}

func TestExtractResource_InvalidURL(t *testing.T) {
	token := jwt.New()
	token.Set(jwt.AudienceKey, []string{"invalid-url"})

	resource, err := extractResource(token)
	assert.Error(t, err)
	assert.Nil(t, resource)
}

func TestExtractResource_MissingAudience(t *testing.T) {
	token := jwt.New()

	resource, err := extractResource(token)
	assert.Error(t, err)
	assert.Nil(t, resource)
}

// Tests for extractExtra

func TestExtractExtra_WithCustomClaims(t *testing.T) {
	token := jwt.New()
	token.Set(jwt.IssuerKey, "https://example.com") // Standard claim
	token.Set("custom_claim1", "value1")            // Custom claim
	token.Set("custom_claim2", 123)                 // Custom claim
	token.Set("client_id", "test-client")           // Standard claim

	extra := extractExtra(token)
	assert.NotNil(t, extra)
	assert.Equal(t, "value1", extra["custom_claim1"])
	assert.Equal(t, 123, extra["custom_claim2"])
	assert.NotContains(t, extra, "iss")       // Standard claims should be excluded
	assert.NotContains(t, extra, "client_id") // Standard claims should be excluded
}

func TestExtractExtra_NoCustomClaims(t *testing.T) {
	token := jwt.New()
	token.Set(jwt.IssuerKey, "https://example.com")
	token.Set("client_id", "test-client")

	extra := extractExtra(token)
	assert.Nil(t, extra) // Should return nil for omitempty
}

// Tests for AddIssuerURL

func TestAddIssuerURL_Success(t *testing.T) {
	ctx := context.Background()
	_, _, jwksJSON := setupTestKeys(t)

	// Use TLS server for HTTPS
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksJSON))
	}))
	defer server.Close()

	client := httprc.NewClient(
		httprc.WithHTTPClient(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}),
	)

	// Create cache with custom HTTP client
	cache, err := jwk.NewCache(ctx, client)
	require.NoError(t, err)

	verifier := &TokenVerifier{
		cache:       cache,
		issuerToURL: make(map[string]string),
		isRemote:    true,
	}

	err = verifier.AddIssuerURL(ctx, "https://new-issuer.com", server.URL, time.Minute)
	assert.NoError(t, err)
	assert.Equal(t, server.URL, verifier.issuerToURL["https://new-issuer.com"])
}

func TestAddIssuerURL_LocalVerifier(t *testing.T) {
	ctx := context.Background()
	_, _, jwksJSON := setupTestKeys(t)

	cfg := LocalJWKSConfig{
		JWKS: jwksJSON,
	}

	verifier, err := NewLocalTokenVerifier(ctx, cfg)
	require.NoError(t, err)

	err = verifier.AddIssuerURL(ctx, "https://issuer.com", "https://issuer.com/.well-known/jwks.json", time.Minute)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "remote JWKS support is disabled")
}

func TestAddIssuerURL_EmptyURL(t *testing.T) {
	ctx := context.Background()
	_, _, jwksJSON := setupTestKeys(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksJSON))
	}))
	defer server.Close()

	cfg := RemoteJWKSConfig{
		URLs: []string{server.URL},
	}

	verifier, err := NewRemoteTokenVerifier(ctx, cfg)
	require.NoError(t, err)

	err = verifier.AddIssuerURL(ctx, "https://issuer.com", "", time.Minute)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWKS URL cannot be empty")
}

func TestAddIssuerURL_NonHTTPS(t *testing.T) {
	ctx := context.Background()
	_, _, jwksJSON := setupTestKeys(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksJSON))
	}))
	defer server.Close()

	cfg := RemoteJWKSConfig{
		URLs: []string{server.URL},
	}

	verifier, err := NewRemoteTokenVerifier(ctx, cfg)
	require.NoError(t, err)

	err = verifier.AddIssuerURL(ctx, "https://issuer.com", "http://insecure.com/jwks.json", time.Minute)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWKS URL must use HTTPS")
}

// Tests for ClearLocalKeys

func TestClearLocalKeys(t *testing.T) {
	ctx := context.Background()
	_, _, jwksJSON := setupTestKeys(t)

	cfg := LocalJWKSConfig{
		JWKS: jwksJSON,
	}

	verifier, err := NewLocalTokenVerifier(ctx, cfg)
	require.NoError(t, err)

	assert.Equal(t, 1, verifier.localKeySet.Len())

	verifier.ClearLocalKeys()

	assert.Equal(t, 0, verifier.localKeySet.Len())
}

// Integration tests

func TestVerifyAccessToken_RemoteJWKS(t *testing.T) {
	ctx := context.Background()
	privateKey, _, jwksJSON := setupTestKeys(t)

	// Create test server for JWKS
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksJSON))
	}))
	defer server.Close()

	cfg := RemoteJWKSConfig{
		URLs: []string{server.URL},
		IssuerToURL: map[string]string{
			"https://example.com": server.URL,
		},
	}

	verifier, err := NewRemoteTokenVerifier(ctx, cfg)
	require.NoError(t, err)

	// Create valid token
	tokenStr, err := createTestToken(privateKey, "test-key-1", nil)
	require.NoError(t, err)

	authInfo, err := verifier.VerifyAccessToken(ctx, tokenStr)
	assert.NoError(t, err)
	assert.Equal(t, tokenStr, authInfo.Token)
	assert.Equal(t, "test-client", authInfo.ClientID)
}

func TestVerifyAccessToken_MixedMode_LocalKeyFound(t *testing.T) {
	ctx := context.Background()
	privateKey, _, jwksJSON := setupTestKeys(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksJSON))
	}))
	defer server.Close()

	cfg := TokenVerifierConfig{
		Local: &LocalJWKSConfig{
			JWKS: jwksJSON,
		},
		Remote: &RemoteJWKSConfig{
			URLs: []string{server.URL},
			IssuerToURL: map[string]string{
				"https://example.com": server.URL,
			},
		},
	}

	verifier, err := NewTokenVerifier(ctx, cfg)
	require.NoError(t, err)

	// Create valid token
	tokenStr, err := createTestToken(privateKey, "test-key-1", nil)
	require.NoError(t, err)

	authInfo, err := verifier.VerifyAccessToken(ctx, tokenStr)
	assert.NoError(t, err)
	assert.Equal(t, tokenStr, authInfo.Token)
}
