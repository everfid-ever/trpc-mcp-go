package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/errors"
)

// ClientAuthenticationMiddlewareOptions contains options for client authentication middleware
type ClientAuthenticationMiddlewareOptions struct {
	// ClientsStore is a store used to read information about registered OAuth clients
	ClientsStore server.OAuthClientsStoreInterface
}

// ClientAuthenticatedRequest represents the request schema for client authentication
type ClientAuthenticatedRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
}

// clientInfoKeyType 用于标识存储OAuthClientInformationFull的上下文键
type clientInfoKeyType struct{}

// validateClientRequest validates the client authentication request
func validateClientRequest(req *ClientAuthenticatedRequest) error {
	if req.ClientID == "" {
		return errors.NewOAuthError(errors.ErrInvalidRequest, "client_id is required", "")
	}
	return nil
}

// writeErrorResponse writes an OAuth error response to the HTTP response writer
func writeErrorResponse(w http.ResponseWriter, oauthErr errors.OAuthError) {
	var status int
	if oauthErr.ErrorCode == errors.ErrServerError.Error() {
		status = http.StatusInternalServerError
	} else {
		status = http.StatusBadRequest
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(oauthErr.ToResponseStruct())
}

// AuthenticateClient returns an HTTP middleware function for client authentication
func AuthenticateClient(options ClientAuthenticationMiddlewareOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Handle panics and convert to server errors
			// fixme panic的捕获应该由开发者的全局中间件实现，且sdk不应做panic错误转换，保证透明
			defer func() {
				if rec := recover(); rec != nil {
					serverError := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
					writeErrorResponse(w, serverError)
				}
			}()

			// Parse request body
			var reqData ClientAuthenticatedRequest
			if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
				serverErr := errors.NewOAuthError(errors.ErrInvalidRequest, "Invalid request body", "")
				writeErrorResponse(w, serverErr)
				return
			}

			// Validate request
			if err := validateClientRequest(&reqData); err != nil {
				if oauthErr, ok := err.(errors.OAuthError); ok {
					writeErrorResponse(w, oauthErr)
				} else {
					invalidError := errors.NewOAuthError(errors.ErrInvalidRequest, "Invalid client_id", "")
					writeErrorResponse(w, invalidError)
				}
				return
			}

			// Get client from store
			client, err := options.ClientsStore.GetClient(reqData.ClientID)
			if err != nil {
				serverError := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
				writeErrorResponse(w, serverError)
				return
			}

			if client == nil {
				invalidClientError := errors.NewOAuthError(errors.ErrInvalidClient, "Invalid client_id", "")
				writeErrorResponse(w, invalidClientError)
				return
			}

			// If client has a secret, validate it
			if client.ClientSecret != "" {
				// Check if client_secret is required but not provided
				if reqData.ClientSecret == "" {
					invalidClientError := errors.NewOAuthError(errors.ErrInvalidClient, "Client secret is required", "")
					writeErrorResponse(w, invalidClientError)
					return
				}

				// Check if client_secret matches
				if client.ClientSecret != reqData.ClientSecret {
					invalidClientError := errors.NewOAuthError(errors.ErrInvalidClient, "Invalid client_secret", "")
					writeErrorResponse(w, invalidClientError)
					return
				}

				// Check if client_secret has expired
				if client.ClientSecretExpiresAt != nil {
					currentTime := time.Now().Unix()
					if *client.ClientSecretExpiresAt < currentTime {
						invalidClientError := errors.NewOAuthError(errors.ErrInvalidClient, "Client secret has expired", "")
						writeErrorResponse(w, invalidClientError)
						return
					}
				}
			}

			// Add authenticated client to request context
			ctx := context.WithValue(r.Context(), clientInfoKeyType{}, client)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetAuthenticatedClient retrieves the authenticated client from HTTP request context
func GetAuthenticatedClient(r *http.Request) (*auth.OAuthClientInformationFull, bool) {
	client := r.Context().Value(clientInfoKeyType{})
	if client == nil {
		return nil, false
	}

	authenticatedClient, ok := client.(*auth.OAuthClientInformationFull)
	return authenticatedClient, ok
}
