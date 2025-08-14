package handler

import (
	"encoding/json"
	"net/http"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/middleware"
	"trpc.group/trpc-go/trpc-mcp-go/internal/errors"
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
			oauthErr := errors.NewOAuthError(
				errors.ErrMethodNotAllowed,
				"Only GET method is allowed",
				"",
			)
			json.NewEncoder(w).Encode(oauthErr.ToResponseStruct())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(metadata)
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
func SetupMetadataRouter(metadata interface{}) *http.ServeMux {
	mux := http.NewServeMux()

	handler := middleware.CorsMiddleware(
		middleware.AllowedMethods([]string{"GET"})(
			MetadataHandler(metadata), // 使用已有的原生 HTTP 版本
		),
	)

	mux.Handle("/", handler)
	return mux
}
