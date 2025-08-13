package handler

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"net/http"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
)

// MetadataHandler creates a handler for OAuth metadata endpoints
// This matches the original TypeScript implementation that takes metadata as parameter
func MetadataHandler(metadata interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Configure CORS to allow any origin, to make accessible to web-based MCP clients
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight OPTIONS request
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Restrict to only GET method
		if r.Method != "GET" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "method_not_allowed",
				"error_description": "Only GET method is allowed",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(metadata)
	}
}

// MetadataHandlerGin creates a Gin handler for OAuth metadata endpoints
func MetadataHandlerGin(metadata interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Configure CORS to allow any origin, to make accessible to web-based MCP clients
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight OPTIONS request
		if c.Request.Method == "OPTIONS" {
			c.Status(http.StatusOK)
			return
		}

		// Restrict to only GET method
		if c.Request.Method != "GET" {
			c.JSON(http.StatusMethodNotAllowed, gin.H{
				"error":             "method_not_allowed",
				"error_description": "Only GET method is allowed",
			})
			return
		}

		c.JSON(http.StatusOK, metadata)
	}
}

// AuthorizationServerMetadataHandler returns an HTTP handler that serves
// OAuth 2.0 Authorization Server Metadata as defined in RFC 8414.
// This is a utility function for creating metadata dynamically
func AuthorizationServerMetadataHandler(baseURL string, store server.OAuthClientsStoreInterface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")

		meta := auth.OAuthMetadata{
			Issuer:                            baseURL,
			AuthorizationEndpoint:             baseURL + "/authorize",
			TokenEndpoint:                     baseURL + "/token",
			ResponseTypesSupported:            []string{"code"},
			GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
			CodeChallengeMethodsSupported:     []string{"S256"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		}

		// The registration_endpoint is only exposed if dynamic registration is supported.
		if _, ok := store.(server.SupportDynamicClientRegistration); ok {
			reg := baseURL + "/register"
			meta.RegistrationEndpoint = &reg
		}

		_ = json.NewEncoder(w).Encode(meta)
	}
}

// SetupMetadataRouter sets up a router with metadata endpoint
func SetupMetadataRouter(metadata interface{}) *gin.Engine {
	router := gin.New()

	// Configure CORS middleware
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.Status(http.StatusOK)
			return
		}

		c.Next()
	})

	// Restrict HTTP methods
	router.Use(AllowedMethods([]string{"GET"}))

	router.GET("/", MetadataHandlerGin(metadata))

	return router
}
