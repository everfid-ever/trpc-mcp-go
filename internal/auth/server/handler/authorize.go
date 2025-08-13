package handler

import (
	"encoding/json"
	"fmt"
	"github.com/go-playground/validator/v10"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/errors"
)

// AuthorizationHandlerOptions contains configuration for the authorization handler
type AuthorizationHandlerOptions struct {
	Provider server.OAuthServerProvider `json:"provider"`
	// Rate limiting configuration for the authorization endpoint.
	// Set to nil to disable rate limiting for this endpoint.
	RateLimit *RateLimitOptions `json:"rateLimit,omitempty"`
}

// RateLimitOptions contains rate limiting configuration
type RateLimitOptions struct {
	WindowMs        int  `json:"windowMs"`        // Time window in milliseconds
	Max             int  `json:"max"`             // Maximum number of requests
	StandardHeaders bool `json:"standardHeaders"` // Whether to use standard headers
	LegacyHeaders   bool `json:"legacyHeaders"`   // Whether to use legacy headers
}

// ClientAuthorizationParams that must be validated to issue redirects.
type ClientAuthorizationParams struct {
	ClientID    string `json:"client_id" validate:"required"`
	RedirectURI string `json:"redirect_uri,omitempty" validate:"omitempty,url"`
}

// RequestAuthorizationParams that must be validated for a successful authorization request. Failure can be reported to the redirect URI.
type RequestAuthorizationParams struct {
	ResponseType        string `json:"response_type" validate:"required,eq=code"`
	CodeChallenge       string `json:"code_challenge" validate:"required"`
	CodeChallengeMethod string `json:"code_challenge_method" validate:"required,eq=S256"`
	Scope               string `json:"scope,omitempty"`
	State               string `json:"state,omitempty"`
	Resource            string `json:"resource,omitempty" validate:"omitempty,url"`
}

// AuthorizationHandler creates an authorization handler
func AuthorizationHandler(options AuthorizationHandlerOptions) http.Handler {
	mux := http.NewServeMux()

	// Create validator
	validate := validator.New()

	// Rate limiting middleware (if enabled)
	var rateLimitMiddleware func(http.Handler) http.Handler
	if options.RateLimit != nil {
		rateLimitMiddleware = createRateLimitMiddleware(*options.RateLimit)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set cache control headers
		w.Header().Set("Cache-Control", "no-store")

		// Only allow GET and POST methods
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse form data (for POST requests)
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				serverError := errors.NewOAuthError(errors.ErrServerError, "Failed to parse form data", "")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(serverError.ToResponseStruct())
				return
			}
		}

		// In the authorization flow, errors are split into two categories:
		// 1. Pre-redirect errors (direct response with 400)
		// 2. Post-redirect errors (redirect with error parameters)

		// Phase 1: Validate client_id and redirect_uri. Any errors here must be direct responses.
		var clientID, redirectURI string
		var client *auth.OAuthClientInformationFull

		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					// Pre-redirect errors - return direct response
					var oauthErr errors.OAuthError
					var ok bool
					if oauthErr, ok = recovered.(errors.OAuthError); !ok {
						oauthErr = errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
					}

					status := http.StatusBadRequest
					if oauthErr.ErrorCode == errors.ErrServerError.Error() {
						status = http.StatusInternalServerError
					}

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(status)
					json.NewEncoder(w).Encode(oauthErr.ToResponseStruct())
				}
			}()

			// Parse client authorization parameters
			clientParams := parseClientAuthorizationParams(r)
			if err := validate.Struct(clientParams); err != nil {
				panic(errors.NewOAuthError(errors.ErrInvalidRequest, err.Error(), ""))
			}

			clientID = clientParams.ClientID
			redirectURI = clientParams.RedirectURI

			// Get client information
			var err error
			client, err = options.Provider.ClientsStore().GetClient(clientID)
			if err != nil {
				panic(errors.NewOAuthError(errors.ErrServerError, "Failed to get client", ""))
			}
			if client == nil {
				panic(errors.NewOAuthError(errors.ErrInvalidClient, "Invalid client_id", ""))
			}

			// Validate redirect_uri
			if redirectURI != "" {
				found := false
				for _, uri := range client.RedirectURIs {
					if uri == redirectURI {
						found = true
						break
					}
				}
				if !found {
					panic(errors.NewOAuthError(errors.ErrInvalidRequest, "Unregistered redirect_uri", ""))
				}
			} else if len(client.RedirectURIs) == 1 {
				redirectURI = client.RedirectURIs[0]
			} else {
				panic(errors.NewOAuthError(errors.ErrInvalidRequest, "redirect_uri must be specified when client has multiple registered URIs", ""))
			}
		}()

		// If Phase 1 had errors, the function would have already returned

		// Phase 2: Validate other parameters. Any errors here should go into redirect responses.
		var state string

		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					// Post-redirect errors - redirect with error parameters
					var oauthErr errors.OAuthError
					var ok bool
					if oauthErr, ok = recovered.(errors.OAuthError); !ok {
						oauthErr = errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
					}

					errorRedirect := createErrorRedirect(redirectURI, oauthErr, state)
					http.Redirect(w, r, errorRedirect, http.StatusFound)
				}
			}()

			// Parse and validate authorization parameters
			reqParams := parseRequestAuthorizationParams(r)
			if err := validate.Struct(reqParams); err != nil {
				panic(errors.NewOAuthError(errors.ErrInvalidRequest, err.Error(), ""))
			}

			state = reqParams.State

			// Validate scopes
			var requestedScopes []string
			if reqParams.Scope != "" {
				requestedScopes = strings.Split(reqParams.Scope, " ")
				allowedScopes := make(map[string]bool)

				// Check if client.Scope is not nil and not empty string
				if client.Scope != nil && *client.Scope != "" {
					for _, scope := range strings.Split(*client.Scope, " ") {
						allowedScopes[scope] = true
					}
				}

				// Check each requested scope against allowed scopes
				for _, scope := range requestedScopes {
					if !allowedScopes[scope] {
						panic(errors.NewOAuthError(errors.ErrInvalidScope, fmt.Sprintf("Client was not registered with scope %s", scope), ""))
					}
				}
			}

			// All validation passed, proceed with authorization
			var resourceURL *url.URL
			if reqParams.Resource != "" {
				var err error
				resourceURL, err = url.Parse(reqParams.Resource)
				if err != nil {
					panic(errors.NewOAuthError(errors.ErrInvalidRequest, "Invalid resource URL", ""))
				}
			}

			authParams := server.AuthorizationParams{
				State:         state,
				Scopes:        requestedScopes,
				RedirectURI:   redirectURI,
				CodeChallenge: reqParams.CodeChallenge,
				Resource:      resourceURL,
			}

			// Pass value instead of pointer
			if err := options.Provider.Authorize(*client, authParams, w, r); err != nil {
				panic(errors.NewOAuthError(errors.ErrServerError, "Authorization failed", ""))
			}
		}()
	})

	// Apply rate limiting middleware (if enabled)
	if rateLimitMiddleware != nil {
		handler = rateLimitMiddleware(handler).(http.HandlerFunc)
	}

	mux.Handle("/", handler)
	return mux
}

// parseClientAuthorizationParams parses client authorization parameters
func parseClientAuthorizationParams(r *http.Request) ClientAuthorizationParams {
	var params ClientAuthorizationParams

	if r.Method == http.MethodPost {
		params.ClientID = r.FormValue("client_id")
		params.RedirectURI = r.FormValue("redirect_uri")
	} else {
		query := r.URL.Query()
		params.ClientID = query.Get("client_id")
		params.RedirectURI = query.Get("redirect_uri")
	}

	return params
}

// parseRequestAuthorizationParams parses request authorization parameters
func parseRequestAuthorizationParams(r *http.Request) RequestAuthorizationParams {
	var params RequestAuthorizationParams

	if r.Method == http.MethodPost {
		params.ResponseType = r.FormValue("response_type")
		params.CodeChallenge = r.FormValue("code_challenge")
		params.CodeChallengeMethod = r.FormValue("code_challenge_method")
		params.Scope = r.FormValue("scope")
		params.State = r.FormValue("state")
		params.Resource = r.FormValue("resource")
	} else {
		query := r.URL.Query()
		params.ResponseType = query.Get("response_type")
		params.CodeChallenge = query.Get("code_challenge")
		params.CodeChallengeMethod = query.Get("code_challenge_method")
		params.Scope = query.Get("scope")
		params.State = query.Get("state")
		params.Resource = query.Get("resource")
	}

	return params
}

// createErrorRedirect creates a redirect URL with error parameters
func createErrorRedirect(redirectURI string, err errors.OAuthError, state string) string {
	errorURL, _ := url.Parse(redirectURI)
	query := errorURL.Query()

	query.Set("error", err.ErrorCode)
	query.Set("error_description", err.Message)

	if err.ErrorURI != "" {
		query.Set("error_uri", err.ErrorURI)
	}

	if state != "" {
		query.Set("state", state)
	}

	errorURL.RawQuery = query.Encode()
	return errorURL.String()
}

// createRateLimitMiddleware creates rate limiting middleware
func createRateLimitMiddleware(options RateLimitOptions) func(http.Handler) http.Handler {
	// Simple in-memory rate limiting implementation
	// In production, you might want to use a more sophisticated rate limiting library like github.com/go-redis/redis_rate
	requestCounts := make(map[string][]time.Time)

	windowDuration := time.Duration(options.WindowMs) * time.Millisecond
	if windowDuration == 0 {
		windowDuration = 15 * time.Minute // Default 15 minutes
	}

	maxRequests := options.Max
	if maxRequests == 0 {
		maxRequests = 100 // Default 100 requests
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := getClientIP(r)
			now := time.Now()

			// Clean up expired request records
			if times, exists := requestCounts[clientIP]; exists {
				var validTimes []time.Time
				for _, t := range times {
					if now.Sub(t) < windowDuration {
						validTimes = append(validTimes, t)
					}
				}
				requestCounts[clientIP] = validTimes
			}

			// Check if limit is exceeded
			if len(requestCounts[clientIP]) >= maxRequests {
				tooManyErr := errors.NewOAuthError(errors.ErrTooManyRequests, "You have exceeded the rate limit for authorization requests", "")

				if options.StandardHeaders {
					w.Header().Set("RateLimit-Limit", strconv.Itoa(maxRequests))
					w.Header().Set("RateLimit-Remaining", "0")
					w.Header().Set("RateLimit-Reset", strconv.FormatInt(now.Add(windowDuration).Unix(), 10))
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(tooManyErr.ToResponseStruct())
				return
			}

			// Record current request
			requestCounts[clientIP] = append(requestCounts[clientIP], now)

			// Set rate limit headers
			if options.StandardHeaders {
				remaining := maxRequests - len(requestCounts[clientIP])
				w.Header().Set("RateLimit-Limit", strconv.Itoa(maxRequests))
				w.Header().Set("RateLimit-Remaining", strconv.Itoa(remaining))
				w.Header().Set("RateLimit-Reset", strconv.FormatInt(now.Add(windowDuration).Unix(), 10))
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getClientIP gets the client IP address
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Use RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}

	return ip
}
