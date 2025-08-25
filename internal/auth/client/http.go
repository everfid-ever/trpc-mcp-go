package client

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	mcp "trpc.group/trpc-go/trpc-mcp-go"

	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
)

// OAuth2HTTPReqHandler is an HTTP request handler with OAuth 2.1 support.
// It automatically injects the Authorization header for all requests
// and handles token caching and refresh logic.
type OAuth2HTTPReqHandler struct {
	// underlying HTTP request handler
	base mcp.HTTPReqHandler
	// OAuth client provider
	provider OAuthClientProvider
	// target server URL
	serverUrl string
	// custom HTTP fetch function
	fetchFn auth.FetchFunc

	// Token management
	tokenMu sync.RWMutex
	// cached OAuth tokens
	cachedToken *auth.OAuthTokens
	// last refresh timestamp
	lastRefresh time.Time
}

// OAuth2HTTPReqHandlerOptions defines configuration options for OAuth2HTTPReqHandler.
type OAuth2HTTPReqHandlerOptions struct {
	// underlying HTTP request handler, use default if nil
	Base mcp.HTTPReqHandler
	// OAuth client provider (required)
	Provider OAuthClientProvider
	// target server URL (required)
	ServerUrl string
	// custom HTTP fetch function, defaults to http.DefaultClient
	FetchFn auth.FetchFunc
}

// NewOAuth2HTTPReqHandler creates a new OAuth2HTTPReqHandler.
func NewOAuth2HTTPReqHandler(opts OAuth2HTTPReqHandlerOptions) (*OAuth2HTTPReqHandler, error) {
	if opts.Provider == nil {
		return nil, fmt.Errorf("OAuth provider is required")
	}
	if opts.ServerUrl == "" {
		return nil, fmt.Errorf("server URL is required")
	}

	base := opts.Base
	if base == nil {
		// Use default HTTP request handler
		base = &defaultHTTPReqHandler{}
	}

	fetchFn := opts.FetchFn
	if fetchFn == nil {
		fetchFn = func(url string, req *http.Request) (*http.Response, error) {
			return http.DefaultClient.Do(req)
		}
	}

	return &OAuth2HTTPReqHandler{
		base:      base,
		provider:  opts.Provider,
		serverUrl: opts.ServerUrl,
		fetchFn:   fetchFn,
	}, nil
}

// Handle processes an HTTP request, automatically injecting the OAuth access token.
func (h *OAuth2HTTPReqHandler) Handle(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error) {
	// Retrieve a valid access token
	token, err := h.getValidToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get valid token: %w", err)
	}

	// Inject Authorization header
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// Send the request via the underlying handler
	resp, err := h.base.Handle(ctx, client, req)

	// If unauthorized, try refreshing the token and retry once
	if err == nil && resp.StatusCode == 401 {
		if retryResp, retryErr := h.handleUnauthorized(ctx, client, req); retryErr == nil {
			resp.Body.Close() // close original response body
			return retryResp, nil
		}
	}

	return resp, err
}

// getValidToken retrieves a valid access token, refreshing if necessary.
func (h *OAuth2HTTPReqHandler) getValidToken(ctx context.Context) (string, error) {
	h.tokenMu.RLock()

	// Return cached token if still valid
	if h.cachedToken != nil && !h.isTokenExpired() {
		token := h.cachedToken.AccessToken
		h.tokenMu.RUnlock()
		return token, nil
	}

	h.tokenMu.RUnlock()

	// Upgrade to write lock to refresh token
	h.tokenMu.Lock()
	defer h.tokenMu.Unlock()

	// Double-check in case another goroutine refreshed the token
	if h.cachedToken != nil && !h.isTokenExpired() {
		return h.cachedToken.AccessToken, nil
	}

	// Request tokens from provider
	tokens, err := h.provider.Tokens()
	if err != nil {
		return "", fmt.Errorf("failed to get tokens from provider: %w", err)
	}

	if tokens == nil {
		return "", fmt.Errorf("no tokens available, authorization required")
	}

	// Update cache
	h.cachedToken = tokens
	h.lastRefresh = time.Now()

	// Check expiration
	if h.isTokenExpired() {
		// Attempt to refresh token
		if err := h.refreshTokenInternal(ctx); err != nil {
			return "", fmt.Errorf("failed to refresh token: %w", err)
		}
	}

	return h.cachedToken.AccessToken, nil
}

// handleUnauthorized handles 401 Unauthorized by refreshing the token and retrying the request.
func (h *OAuth2HTTPReqHandler) handleUnauthorized(ctx context.Context, client *http.Client, originalReq *http.Request) (*http.Response, error) {
	h.tokenMu.Lock()
	defer h.tokenMu.Unlock()

	// Invalidate cached token
	h.cachedToken = nil

	// Attempt token refresh
	if err := h.refreshTokenInternal(ctx); err != nil {
		return nil, fmt.Errorf("failed to refresh token after 401: %w", err)
	}

	// Clone and retry the request with new token
	retryReq := originalReq.Clone(ctx)
	retryReq.Header.Set("Authorization", "Bearer "+h.cachedToken.AccessToken)

	return h.base.Handle(ctx, client, retryReq)
}

// refreshTokenInternal performs internal token refresh logic.
func (h *OAuth2HTTPReqHandler) refreshTokenInternal(ctx context.Context) error {
	// Retrieve current tokens
	tokens, err := h.provider.Tokens()
	if err != nil {
		return err
	}

	if tokens == nil || tokens.RefreshToken == nil || *tokens.RefreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	// Perform full authorization flow (including token refresh)
	result, err := Auth(h.provider, auth.AuthOptions{
		ServerUrl: h.serverUrl,
		FetchFn:   h.fetchFn,
	})
	if err != nil {
		return err
	}

	if *result != AuthResultAuthorized {
		return fmt.Errorf("authentication failed, result: %s", *result)
	}

	// Get updated tokens
	newTokens, err := h.provider.Tokens()
	if err != nil {
		return err
	}

	if newTokens == nil {
		return fmt.Errorf("no tokens received after refresh")
	}

	// Update cache
	h.cachedToken = newTokens
	h.lastRefresh = time.Now()

	return nil
}

// isTokenExpired checks if the cached token has expired.
func (h *OAuth2HTTPReqHandler) isTokenExpired() bool {
	if h.cachedToken == nil {
		return true
	}

	// If explicit expiration is available
	if h.cachedToken.ExpiresIn != nil {
		expiryTime := h.lastRefresh.Add(time.Duration(*h.cachedToken.ExpiresIn) * time.Second)
		// Consider token expired 30s earlier to avoid edge cases
		return time.Now().After(expiryTime.Add(-30 * time.Second))
	}

	// Default: assume token valid for up to 50 minutes
	return time.Since(h.lastRefresh) > 50*time.Minute
}

// InvalidateToken invalidates the cached token, forcing a refresh on next request.
func (h *OAuth2HTTPReqHandler) InvalidateToken() {
	h.tokenMu.Lock()
	defer h.tokenMu.Unlock()
	h.cachedToken = nil
}

// defaultHTTPReqHandler is the default implementation of HTTPReqHandler, which simply forwards the request.
type defaultHTTPReqHandler struct{}

func (h *defaultHTTPReqHandler) Handle(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error) {
	return client.Do(req)
}
