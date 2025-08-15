package handler

import (
	"encoding/json"
	"net/http"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/middleware"
)

// MetadataHandler creates a handler for metadata endpoints
// This matches the TypeScript implementation using middleware composition
func MetadataHandler(metadata interface{}) http.HandlerFunc {
	// Core handler that just serves JSON - no CORS or method validation
	coreHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(metadata)
	})

	middlewareHandler := middleware.CorsMiddleware(
		middleware.AllowedMethods([]string{"GET"})(coreHandler),
	)

	// Convert http.Handler to http.HandlerFunc
	return func(w http.ResponseWriter, r *http.Request) {
		middlewareHandler.ServeHTTP(w, r)
	}
}

// AuthorizationServerMetadataHandler returns an HTTP handler that serves
// OAuth 2.0 Authorization Server Metadata as defined in RFC 8414.
func AuthorizationServerMetadataHandler(baseURL string, store server.OAuthClientsStoreInterface) http.HandlerFunc {
	// Build the metadata
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

	// Return a handler with Cache-Control header
	coreHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(meta)
	})

	// Apply the same middleware stack as MetadataHandler
	middlewareHandler := middleware.CorsMiddleware(
		middleware.AllowedMethods([]string{"GET"})(coreHandler),
	)

	// Convert http.Handler to http.HandlerFunc
	return func(w http.ResponseWriter, r *http.Request) {
		middlewareHandler.ServeHTTP(w, r)
	}
}

// SetupMetadataRouter sets up a router with metadata endpoint
// Since MetadataHandler already includes middleware, this is now very simple
func SetupMetadataRouter(metadata interface{}) *http.ServeMux {
	mux := http.NewServeMux()
	// No need for additional middleware - MetadataHandler includes everything
	mux.Handle("/", MetadataHandler(metadata))
	return mux
}
