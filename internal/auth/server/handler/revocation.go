package handler

import (
	"github.com/gin-gonic/gin"
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
	RateLimit *RateLimitConfig // Set to nil to disable rate limiting for this endpoint
}

// RateLimitConfig rate limiting configuration
type RateLimitConfig struct {
	WindowMs int  // Window duration in milliseconds
	Max      int  // Maximum requests per window
	Burst    int  // Burst size for rate limiter
	Enabled  bool // Whether rate limiting is enabled
}

// RevocationHandler creates a handler for OAuth token revocation
func RevocationHandler(opts RevocationHandlerOptions) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Configure CORS to allow any origin, to make accessible to web-based MCP clients
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight requests
		if c.Request.Method == "OPTIONS" {
			c.Status(http.StatusOK)
			return
		}

		// Restrict to POST method only
		if c.Request.Method != "POST" {
			c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "method_not_allowed", "error_description": "Only POST method is allowed"})
			return
		}

		// Apply rate limiting unless explicitly disabled
		if opts.RateLimit != nil && opts.RateLimit.Enabled {
			limiter := rate.NewLimiter(
				rate.Every(time.Duration(opts.RateLimit.WindowMs)*time.Millisecond/time.Duration(opts.RateLimit.Max)),
				opts.RateLimit.Burst,
			)

			if !limiter.Allow() {
				tooManyRequestsError := errors.NewOAuthError(
					errors.ErrTooManyRequests,
					"You have exceeded the rate limit for token revocation requests",
					"",
				)
				c.JSON(http.StatusTooManyRequests, tooManyRequestsError.ToResponseStruct())
				return
			}
		} else if opts.RateLimit == nil {
			// Default rate limiting: 50 requests per 15 minutes
			limiter := rate.NewLimiter(rate.Every(18*time.Second), 10) // 50 requests per 15 minutes ≈ 1 request per 18 seconds

			if !limiter.Allow() {
				tooManyRequestsError := errors.NewOAuthError(
					errors.ErrTooManyRequests,
					"You have exceeded the rate limit for token revocation requests",
					"",
				)
				c.JSON(http.StatusTooManyRequests, tooManyRequestsError.ToResponseStruct())
				return
			}
		}

		// Authenticate and extract client details
		client, err := AuthenticateClient(c, opts.Provider.ClientsStore())
		if err != nil {
			if oauthErr, ok := err.(errors.OAuthError); ok {
				status := http.StatusBadRequest
				if oauthErr.ErrorCode == errors.ErrServerError.Error() {
					status = http.StatusInternalServerError
				}
				c.JSON(status, oauthErr.ToResponseStruct())
				return
			}
			serverError := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
			c.JSON(http.StatusInternalServerError, serverError.ToResponseStruct())
			return
		}

		c.Header("Cache-Control", "no-store")

		// Parse request body
		var reqBody auth.OAuthTokenRevocationRequest
		if err := c.ShouldBindJSON(&reqBody); err != nil {
			invalidReqError := errors.NewOAuthError(errors.ErrInvalidRequest, err.Error(), "")
			c.JSON(http.StatusBadRequest, invalidReqError.ToResponseStruct())
			return
		}

		// Validate request
		if reqBody.Token == "" {
			invalidReqError := errors.NewOAuthError(errors.ErrInvalidRequest, "token is required", "")
			c.JSON(http.StatusBadRequest, invalidReqError.ToResponseStruct())
			return
		}

		if client == nil {
			// This should never happen
			serverError := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
			c.JSON(http.StatusInternalServerError, serverError.ToResponseStruct())
			return
		}

		// Revoke token - since OAuthServerProvider embeds SupportTokenRevocation,
		// we can directly call RevokeToken method
		err = opts.Provider.RevokeToken(*client, reqBody)
		if err != nil {
			if oauthErr, ok := err.(errors.OAuthError); ok {
				status := http.StatusBadRequest
				if oauthErr.ErrorCode == errors.ErrServerError.Error() {
					status = http.StatusInternalServerError
				}
				c.JSON(status, oauthErr.ToResponseStruct())
				return
			}
			serverError := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
			c.JSON(http.StatusInternalServerError, serverError.ToResponseStruct())
			return
		}

		c.JSON(http.StatusOK, gin.H{})
	}
}

// AuthenticateClient authenticates the client from the request
func AuthenticateClient(c *gin.Context, store *server.OAuthClientsStore) (*auth.OAuthClientInformationFull, error) {
	// Implementation would extract client credentials from Authorization header
	// or from request body and validate against the clients store
	// This is a placeholder - actual implementation depends on your auth mechanism
	return nil, errors.NewOAuthError(errors.ErrServerError, "Client authentication not implemented", "")
}
