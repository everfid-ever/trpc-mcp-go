package handler

import (
	"encoding/json"
	"golang.org/x/time/rate"
	"net/http"
	"time"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/errors"
)

// RevocationHandlerOptions configuration for the token revocation endpoint
type RevocationHandlerOptions struct {
	Provider  server.OAuthServerProvider
	RateLimit *RevocationRateLimitConfig // Set to nil to disable rate limiting for this endpoint
}

// RevocationRateLimitConfig rate limiting configuration
type RevocationRateLimitConfig struct {
	WindowMs int  // Window duration in milliseconds
	Max      int  // Maximum requests per window
	Burst    int  // Burst size for rate limiter
	Enabled  bool // Whether rate limiting is enabled
}

// RevocationHandler creates a handler for OAuth token revocation
func RevocationHandler(opts RevocationHandlerOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Configure CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Apply rate limiting unless explicitly disabled
		if opts.RateLimit != nil && opts.RateLimit.Enabled {
			limiter := rate.NewLimiter(
				rate.Every(time.Duration(opts.RateLimit.WindowMs)*time.Millisecond/time.Duration(opts.RateLimit.Max)),
				opts.RateLimit.Burst,
			)

			if !limiter.Allow() {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)

				tooManyRequestsError := errors.NewOAuthError(
					errors.ErrTooManyRequests,
					"You have exceeded the rate limit for token revocation requests",
					"",
				)
				json.NewEncoder(w).Encode(tooManyRequestsError.ToResponseStruct())
				return
			}
		} else if opts.RateLimit == nil {
			// Default rate limiting: 50 requests per 15 minutes
			limiter := rate.NewLimiter(rate.Every(18*time.Second), 10)

			if !limiter.Allow() {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)

				tooManyRequestsError := errors.NewOAuthError(
					errors.ErrTooManyRequests,
					"You have exceeded the rate limit for token revocation requests",
					"",
				)
				json.NewEncoder(w).Encode(tooManyRequestsError.ToResponseStruct())
				return
			}
		}

		// Authenticate and extract client details
		client, err := AuthenticateClient(r, opts.Provider.ClientsStore())
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

		// Validate request
		if reqBody.Token == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)

			invalidReqError := errors.NewOAuthError(errors.ErrInvalidRequest, "token is required", "")
			json.NewEncoder(w).Encode(invalidReqError.ToResponseStruct())
			return
		}

		if client == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)

			serverError := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
			json.NewEncoder(w).Encode(serverError.ToResponseStruct())
			return
		}

		// Revoke token
		err = opts.Provider.RevokeToken(*client, reqBody)
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
	}
}

// AuthenticateClient authenticates the client from the HTTP request
func AuthenticateClient(r *http.Request, store *server.OAuthClientsStore) (*auth.OAuthClientInformationFull, error) {
	// Implementation would extract client credentials from Authorization header
	// or from request body and validate against the clients store
	// This is a placeholder - actual implementation depends on your auth mechanism
	return nil, errors.NewOAuthError(errors.ErrServerError, "Client authentication not implemented", "")
}
