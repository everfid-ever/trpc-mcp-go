package middleware

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
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

// clientInfoKeyType used to identify the context key storing OAuthClientInformationFull
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
				_ = json.NewEncoder(w).Encode(err.ToResponseStruct())
				audit(false, "invalid client credentials", clientID)
			}

			var reqData ClientAuthenticatedRequest
			var clientID string

			// Priority: Basic Auth first
			if authz := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(authz), "basic ") {
				enc := strings.TrimSpace(authz[len("Basic "):])
				raw, decErr := base64.StdEncoding.DecodeString(enc)
				if decErr != nil {
					setErrorResponse(w, errors.NewOAuthError(errors.ErrInvalidClient, "malformed basic credentials", ""), "")
					return
				}
				parts := strings.SplitN(string(raw), ":", 2)
				if len(parts) != 2 {
					setErrorResponse(w, errors.NewOAuthError(errors.ErrInvalidClient, "malformed basic credentials", ""), "")
					return
				}
				reqData.ClientID, reqData.ClientSecret = parts[0], parts[1]
				clientID = reqData.ClientID
			} else {
				// Non-Basic: buffer and restore Body, support form or JSON
				bodyBytes, _ := io.ReadAll(r.Body)
				_ = r.Body.Close()
				defer func() { r.Body = io.NopCloser(bytes.NewReader(bodyBytes)) }()

				ct := strings.ToLower(r.Header.Get("Content-Type"))
				switch {
				case strings.HasPrefix(ct, "application/x-www-form-urlencoded"):
					formVals, _ := url.ParseQuery(string(bodyBytes))
					reqData.ClientID = formVals.Get("client_id")
					reqData.ClientSecret = formVals.Get("client_secret")
					clientID = reqData.ClientID
				case strings.HasPrefix(ct, "application/json"):
					if err := json.Unmarshal(bodyBytes, &reqData); err != nil {
						setErrorResponse(w, errors.NewOAuthError(errors.ErrInvalidRequest, "Invalid request body", ""), "")
						return
					}
					clientID = reqData.ClientID
				default:
					// Unknown type: maintain compatibility behavior, treat as JSON decode error
					setErrorResponse(w, errors.NewOAuthError(errors.ErrInvalidRequest, "Invalid request body", ""), "")
					return
				}
			}

			// Validate client_id
			if err := validateClientRequest(&reqData); err != nil {
				if oauthErr, ok := err.(errors.OAuthError); ok {
					setErrorResponse(w, oauthErr, clientID)
				} else {
					setErrorResponse(w, errors.NewOAuthError(errors.ErrInvalidRequest, "Invalid client_id", ""), clientID)
				}
				return
			}

			// Read client and validate secret/expiration
			client, err := options.ClientsStore.GetClient(reqData.ClientID)
			if err != nil {
				setErrorResponse(w, errors.NewOAuthError(errors.ErrInvalidClient, "invalid client credentials", ""), clientID)
				return
			}
			if client == nil {
				setErrorResponse(w, errors.NewOAuthError(errors.ErrInvalidClient, "invalid client credentials", ""), clientID)
				return
			}
			if client.ClientSecret != "" {
				if reqData.ClientSecret == "" {
					setErrorResponse(w, errors.NewOAuthError(errors.ErrInvalidClient, "Client secret is required", ""), clientID)
					return
				}
				if client.ClientSecret != reqData.ClientSecret {
					setErrorResponse(w, errors.NewOAuthError(errors.ErrInvalidClient, "Invalid client_secret", ""), clientID)
					return
				}
				if client.ClientSecretExpiresAt != nil {
					now := time.Now().Unix()
					if *client.ClientSecretExpiresAt != 0 && *client.ClientSecretExpiresAt < now {
						setErrorResponse(w, errors.NewOAuthError(errors.ErrInvalidClient, "Client secret has expired", ""), clientID)
						return
					}
				}
			}

			audit(true, "client authenticated", clientID)
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
