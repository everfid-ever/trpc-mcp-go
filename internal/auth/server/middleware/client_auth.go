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

// AuthenticateClient returns an HTTP middleware function for client authentication
func AuthenticateClient(options ClientAuthenticationMiddlewareOptions, onDecision OnDecision) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 审计辅助函数
			audit := func(allowed bool, reason string, clientID string) {
				if onDecision != nil {
					onDecision(Decision{
						Allowed:   allowed,
						Reason:    reason,
						ClientID:  clientID,
						Resource:  r.URL.Path,
						Action:    r.Method,
						TraceID:   r.Header.Get("X-Request-ID"),
						Timestamp: time.Now(),
					})
				}
			}
			// 处理错误并设置响应函数
			setErrorResponse := func(w http.ResponseWriter, err errors.OAuthError, clientID string) {
				var statusCode int
				switch err.ErrorCode {
				case errors.ErrInvalidClient.Error():
					statusCode = http.StatusUnauthorized
				case errors.ErrInvalidRequest.Error():
					statusCode = http.StatusBadRequest
				case errors.ErrServerError.Error():
					statusCode = http.StatusInternalServerError
				default:
					statusCode = http.StatusBadRequest
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(statusCode)
				json.NewEncoder(w).Encode(err.ToResponseStruct())

				//审计失败
				audit(false, "invalid client credentials", clientID)
			}

			// Parse request body
			var reqData ClientAuthenticatedRequest
			if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
				serverErr := errors.NewOAuthError(errors.ErrInvalidRequest, "Invalid request body", "")
				setErrorResponse(w, serverErr, "")
				return
			}

			// Validate request
			if err := validateClientRequest(&reqData); err != nil {
				if oauthErr, ok := err.(errors.OAuthError); ok {
					setErrorResponse(w, oauthErr, "")
				} else {
					invalidError := errors.NewOAuthError(errors.ErrInvalidRequest, "Invalid client_id", "")
					setErrorResponse(w, invalidError, reqData.ClientID)
				}
				return
			}

			// Get client from store
			client, err := options.ClientsStore.GetClient(reqData.ClientID)
			if err != nil {
				serverError := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
				setErrorResponse(w, serverError, reqData.ClientID)
				return
			}

			if client == nil {
				invalidClientError := errors.NewOAuthError(errors.ErrInvalidClient, "Invalid client_id", "")
				setErrorResponse(w, invalidClientError, reqData.ClientID)
				return
			}

			// If client has a secret, validate it
			if client.ClientSecret != "" {
				// Check if client_secret is required but not provided
				if reqData.ClientSecret == "" {
					invalidClientError := errors.NewOAuthError(errors.ErrInvalidClient, "Client secret is required", "")
					setErrorResponse(w, invalidClientError, reqData.ClientID)
					return
				}

				// Check if client_secret matches
				if client.ClientSecret != reqData.ClientSecret {
					invalidClientError := errors.NewOAuthError(errors.ErrInvalidClient, "Invalid client_secret", "")
					setErrorResponse(w, invalidClientError, reqData.ClientID)
					return
				}

				// Check if client_secret has expired
				if client.ClientSecretExpiresAt != nil {
					currentTime := time.Now().Unix()
					if *client.ClientSecretExpiresAt < currentTime {
						invalidClientError := errors.NewOAuthError(errors.ErrInvalidClient, "Client secret has expired", "")
						setErrorResponse(w, invalidClientError, reqData.ClientID)
						return
					}
				}
			}

			// 审计成功
			audit(true, "client authenticated", reqData.ClientID)

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
