package handler

import (
	"encoding/json"
	"golang.org/x/time/rate"
	"net/http"
	"time"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/middleware"
	"trpc.group/trpc-go/trpc-mcp-go/internal/errors"
)

// RevocationHandlerOptions configuration for the token revocation endpoint
type RevocationHandlerOptions struct {
	Provider  server.OAuthServerProvider
	RateLimit *RevocationRateLimitConfig // Set to nil to disable rate limiting for this endpoint
}

// RevocationRateLimitConfig rate limiting configuration
type RevocationRateLimitConfig struct {
	WindowMs int // Window duration in milliseconds
	Max      int // Maximum requests per window
}

// RevocationHandler creates a handler for OAuth token revocation with client authentication middleware
func RevocationHandler(opts RevocationHandlerOptions) http.Handler {
	// Check if provider supports token revocation
	if opts.Provider.RevokeToken == nil {
		panic("Auth provider does not support revoking tokens")
	}

	// Create the core handler
	coreHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set cache control header
		w.Header().Set("Cache-Control", "no-store")

		// Parse request body
		var reqBody auth.OAuthTokenRevocationRequest
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)

			invalidReqError := errors.NewOAuthError(errors.ErrInvalidRequest, err.Error(), "")
			json.NewEncoder(w).Encode(invalidReqError.ToResponseStruct())
			return
		}

		// Validate request - token is required
		if reqBody.Token == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)

			invalidReqError := errors.NewOAuthError(errors.ErrInvalidRequest, "token is required", "")
			json.NewEncoder(w).Encode(invalidReqError.ToResponseStruct())
			return
		}

		// Get authenticated client from context (set by clientAuth middleware)
		client, ok := middleware.GetAuthenticatedClient(r)
		if !ok {
			// This should never happen if middleware is properly configured
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)

			serverError := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
			json.NewEncoder(w).Encode(serverError.ToResponseStruct())
			return
		}

		// Revoke the token
		err := opts.Provider.RevokeToken(*client, reqBody)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")

			if oauthErr, ok := err.(errors.OAuthError); ok {
				status := http.StatusBadRequest
				if oauthErr.ErrorCode == errors.ErrServerError.Error() {
					status = http.StatusInternalServerError
				}
				w.WriteHeader(status)
				json.NewEncoder(w).Encode(oauthErr.ToResponseStruct())
				return
			}

			w.WriteHeader(http.StatusInternalServerError)
			serverError := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
			json.NewEncoder(w).Encode(serverError.ToResponseStruct())
			return
		}

		// Success response - empty JSON object per OAuth 2.1 spec
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("{}"))
	})

	// Apply middlewares in order (similar to Express middleware chain)
	var handler http.Handler = coreHandler

	// Apply client authentication middleware
	handler = middleware.AuthenticateClient(middleware.ClientAuthenticationMiddlewareOptions{
		ClientsStore: opts.Provider.ClientsStore(),
	})(handler)

	// Apply rate limiting middleware unless explicitly disabled
	if opts.RateLimit != nil {
		windowDuration := time.Duration(opts.RateLimit.WindowMs) * time.Millisecond
		limit := rate.Every(windowDuration / time.Duration(opts.RateLimit.Max))
		limiter := rate.NewLimiter(limit, opts.RateLimit.Max)

		handler = middleware.RateLimitMiddleware(limiter)(handler)
	} else {
		// Default rate limiting: 50 requests per 15 minutes
		limiter := rate.NewLimiter(rate.Every(18*time.Second), 50)
		handler = middleware.RateLimitMiddleware(limiter)(handler)
	}

	// Apply method restriction middleware (only POST allowed)
	handler = middleware.AllowedMethods([]string{"POST"})(handler)

	// Apply CORS middleware
	handler = middleware.CorsMiddleware(handler)

	return handler
}
