package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

// Context key type for storing authenticated client
type contextKey string

const ClientContextKey contextKey = "authenticated_client"

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
			defer func() {
				if rec := recover(); rec != nil {
					serverError := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
					writeErrorResponse(w, serverError)
				}
			}()

			// Parse request body
			body, err := io.ReadAll(r.Body)
			if err != nil {
				invalidError := errors.NewOAuthError(errors.ErrInvalidRequest, fmt.Sprintf("Error reading request body: %v", err), "")
				writeErrorResponse(w, invalidError)
				return
			}
			r.Body.Close()

			var req ClientAuthenticatedRequest
			if err := json.Unmarshal(body, &req); err != nil {
				invalidError := errors.NewOAuthError(errors.ErrInvalidRequest, fmt.Sprintf("Invalid JSON: %v", err), "")
				writeErrorResponse(w, invalidError)
				return
			}

			// Validate request
			if err := validateClientRequest(&req); err != nil {
				if oauthErr, ok := err.(errors.OAuthError); ok {
					writeErrorResponse(w, oauthErr)
				} else {
					invalidError := errors.NewOAuthError(errors.ErrInvalidRequest, err.Error(), "")
					writeErrorResponse(w, invalidError)
				}
				return
			}

			// Get client from store
			client, err := options.ClientsStore.GetClient(req.ClientID)
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
				if req.ClientSecret == "" {
					invalidClientError := errors.NewOAuthError(errors.ErrInvalidClient, "Client secret is required", "")
					writeErrorResponse(w, invalidClientError)
					return
				}

				// Check if client_secret matches
				if client.ClientSecret != req.ClientSecret {
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
			ctx := context.WithValue(r.Context(), ClientContextKey, client)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetAuthenticatedClient retrieves the authenticated client from HTTP request context
func GetAuthenticatedClient(r *http.Request) (*auth.OAuthClientInformationFull, bool) {
	client := r.Context().Value(ClientContextKey)
	if client == nil {
		return nil, false
	}

	authenticatedClient, ok := client.(*auth.OAuthClientInformationFull)
	return authenticatedClient, ok
}
