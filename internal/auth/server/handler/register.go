package handler

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
	"trpc.group/trpc-go/trpc-mcp-go/internal/errors"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/time/rate"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
)

// ClientRegistrationHandlerOptions configuration for client registration handler
type ClientRegistrationHandlerOptions struct {
	// A store used to save information about dynamically registered OAuth clients.
	ClientsStore server.SupportDynamicClientRegistration

	// The number of seconds after which to expire issued client secrets, or 0 to prevent expiration of client secrets (not recommended).
	// If not set, defaults to 30 days.
	ClientSecretExpirySeconds *int

	// Rate limiting configuration for the client registration endpoint.
	// Set to nil to disable rate limiting for this endpoint.
	// Registration endpoints are particularly sensitive to abuse and should be rate limited.
	RateLimit *RateLimitConfig

	// Whether to generate a client ID before calling the client registration endpoint.
	// If not set, defaults to true.
	ClientIdGeneration *bool
}

type RateLimitConfig struct {
	WindowMs int // Time window in milliseconds
	Max      int // Maximum requests per window
}

const DEFAULT_CLIENT_SECRET_EXPIRY_SECONDS = 30 * 24 * 60 * 60 // 30 days

// AllowedMethods middleware to restrict HTTP methods
func AllowedMethods(methods []string) gin.HandlerFunc {
	allowedMap := make(map[string]bool)
	for _, method := range methods {
		allowedMap[method] = true
	}

	return func(c *gin.Context) {
		if !allowedMap[c.Request.Method] {
			c.JSON(http.StatusMethodNotAllowed, gin.H{
				"error":             "method_not_allowed",
				"error_description": fmt.Sprintf("Method %s not allowed", c.Request.Method),
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

type RateLimiter struct {
	limiter *rate.Limiter
}

func NewRateLimiter(rps rate.Limit, burst int) *RateLimiter {
	return &RateLimiter{
		limiter: rate.NewLimiter(rps, burst),
	}
}

func (rl *RateLimiter) Allow() bool {
	return rl.limiter.Allow()
}

var globalRateLimiter = NewRateLimiter(rate.Every(3*time.Minute), 20) // 20 requests per hour (approximated)

// ClientRegistrationHandler creates a handler for OAuth client registration
func ClientRegistrationHandler(options ClientRegistrationHandlerOptions) gin.HandlerFunc {
	if options.ClientsStore == nil {
		panic("Client registration store does not support registering clients")
	}

	clientSecretExpirySeconds := DEFAULT_CLIENT_SECRET_EXPIRY_SECONDS
	if options.ClientSecretExpirySeconds != nil {
		clientSecretExpirySeconds = *options.ClientSecretExpirySeconds
	}

	clientIdGeneration := true
	if options.ClientIdGeneration != nil {
		clientIdGeneration = *options.ClientIdGeneration
	}

	return func(c *gin.Context) {
		// Configure CORS to allow any origin
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Header("Cache-Control", "no-store")

		// Handle preflight OPTIONS request
		if c.Request.Method == "OPTIONS" {
			c.Status(http.StatusOK)
			return
		}

		// Restrict to only POST method
		if c.Request.Method != "POST" {
			c.JSON(http.StatusMethodNotAllowed, gin.H{
				"error":             "method_not_allowed",
				"error_description": "Only POST method is allowed",
			})
			return
		}

		// Apply rate limiting unless explicitly disabled
		if options.RateLimit != nil {
			if !globalRateLimiter.Allow() {
				errorResp := errors.ErrTooManyRequests
				c.JSON(http.StatusTooManyRequests, errorResp)
				return
			}
		}

		var clientMetadata auth.OAuthClientMetadata
		if err := c.ShouldBindJSON(&clientMetadata); err != nil {
			errorResp := errors.ErrInvalidClientMetadata
			c.JSON(http.StatusBadRequest, errorResp)
			return
		}

		// Validate client metadata (basic validation)
		if err := validateClientMetadata(&clientMetadata); err != nil {
			errorResp := errors.ErrInvalidClientMetadata
			c.JSON(http.StatusBadRequest, errorResp)
			return
		}

		isPublicClient := clientMetadata.TokenEndpointAuthMethod == "none"

		// Generate client credentials
		var clientSecret string
		if !isPublicClient {
			secret, err := generateClientSecret()
			if err != nil {
				errorResp := errors.ErrServerError
				c.JSON(http.StatusInternalServerError, errorResp)
				return
			}
			clientSecret = secret
		}

		clientIdIssuedAt := time.Now().Unix()

		// Calculate client secret expiry time
		clientsDoExpire := clientSecretExpirySeconds > 0
		var clientSecretExpiresAt *int64
		if !isPublicClient {
			if clientsDoExpire {
				expiryTime := clientIdIssuedAt + int64(clientSecretExpirySeconds)
				clientSecretExpiresAt = &expiryTime
			} else {
				zero := int64(0)
				clientSecretExpiresAt = &zero
			}
		}

		// Create client information
		clientInfo := auth.OAuthClientInformationFull{
			OAuthClientMetadata: clientMetadata,
			OAuthClientInformation: auth.OAuthClientInformation{
				ClientSecret:          clientSecret,
				ClientSecretExpiresAt: clientSecretExpiresAt,
			},
		}

		if clientIdGeneration {
			clientId := uuid.New().String()
			clientInfo.OAuthClientInformation.ClientID = clientId
			clientInfo.OAuthClientInformation.ClientIDIssuedAt = &clientIdIssuedAt
		}

		registeredClient, err := options.ClientsStore.RegisterClient(clientInfo)
		if err != nil {
			errorResp := errors.ErrServerError
			c.JSON(http.StatusInternalServerError, errorResp)
			return
		}

		c.JSON(http.StatusCreated, registeredClient)
	}
}

// SetupClientRegistrationRouter sets up a router with client registration endpoint
func SetupClientRegistrationRouter(options ClientRegistrationHandlerOptions) *gin.Engine {
	router := gin.New()

	// Configure CORS middleware
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.Status(http.StatusOK)
			return
		}

		c.Next()
	})

	// Restrict HTTP methods
	router.Use(AllowedMethods([]string{"POST"}))

	router.POST("/", ClientRegistrationHandler(options))

	return router
}

// generateClientSecret generates a random 32-byte hex string
func generateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// validateClientMetadata performs basic validation on client metadata
func validateClientMetadata(metadata *auth.OAuthClientMetadata) error {
	// Add validation logic as needed
	if metadata.TokenEndpointAuthMethod == "" {
		return fmt.Errorf("token_endpoint_auth_method is required")
	}
	return nil
}
