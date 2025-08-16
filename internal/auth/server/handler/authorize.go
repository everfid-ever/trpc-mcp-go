package handler

import (
	"encoding/json"
	"fmt"
	"github.com/go-playground/validator/v10"
	"golang.org/x/time/rate"
	"net/http"
	"net/url"
	"strings"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/middleware"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/pkce"
	"trpc.group/trpc-go/trpc-mcp-go/internal/errors"
)

// AuthorizationHandlerOptions contains configuration for the authorization handler
type AuthorizationHandlerOptions struct {
	Provider  server.OAuthServerProvider `json:"provider"`
	RateLimit *rate.Limiter              `json:"rateLimit,omitempty"` // 使用标准的 rate.Limiter
}

// ClientAuthorizationParams that must be validated to issue redirects.
type ClientAuthorizationParams struct {
	ClientID    string `json:"client_id" validate:"required"`
	RedirectURI string `json:"redirect_uri,omitempty" validate:"omitempty,url"`
}

// RequestAuthorizationParams that must be validated for a successful authorization request.
type RequestAuthorizationParams struct {
	ResponseType        string `json:"response_type" validate:"required,eq=code"`
	CodeChallenge       string `json:"code_challenge" validate:"required"`
	CodeChallengeMethod string `json:"code_challenge_method" validate:"required,eq=S256"`
	Scope               string `json:"scope,omitempty"`
	State               string `json:"state,omitempty"`
	Resource            string `json:"resource,omitempty" validate:"omitempty,url"`
}

// AuthorizationHandler creates an authorization handler
// Returns http.HandlerFunc for consistency with other handlers
func AuthorizationHandler(options AuthorizationHandlerOptions) http.HandlerFunc {
	validate := validator.New()

	// Core handler logic
	coreHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				handleDirectError(w, errors.NewOAuthError(errors.ErrServerError, "Failed to parse form data", ""))
				return
			}
		}

		// Phase 1: Validate client_id and redirect_uri
		_, redirectURI, client, err := validateClientAndRedirect(r, validate, options.Provider)
		if err != nil {
			handleDirectError(w, *err)
			return
		}

		// Phase 2: Validate other parameters and authorize
		if authErr := processAuthorization(r, validate, client, redirectURI, options.Provider, w); authErr != nil {
			state := getStateFromRequest(r)
			errorRedirect := createErrorRedirect(redirectURI, *authErr, state)
			http.Redirect(w, r, errorRedirect, http.StatusFound)
			return
		}
	})

	// Apply middleware if needed
	var handler http.Handler = coreHandler

	// Apply rate limiting using standard middleware
	if options.RateLimit != nil {
		handler = middleware.RateLimitMiddleware(options.RateLimit)(handler)
	}

	// Apply method restrictions (GET and POST allowed)
	handler = middleware.AllowedMethods([]string{"GET", "POST"})(handler)

	// Convert back to http.HandlerFunc
	return func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}
}

// validateClientAndRedirect validates client_id and redirect_uri
func validateClientAndRedirect(r *http.Request, validate *validator.Validate, provider server.OAuthServerProvider) (string, string, *auth.OAuthClientInformationFull, *errors.OAuthError) {
	clientParams := parseClientAuthorizationParams(r)
	if err := validate.Struct(clientParams); err != nil {
		oauthErr := errors.NewOAuthError(errors.ErrInvalidRequest, err.Error(), "")
		return "", "", nil, &oauthErr
	}

	clientID := clientParams.ClientID
	redirectURI := clientParams.RedirectURI

	client, err := provider.ClientsStore().GetClient(clientID)
	if err != nil {
		oauthErr := errors.NewOAuthError(errors.ErrServerError, "Failed to get client", "")
		return "", "", nil, &oauthErr
	}
	if client == nil {
		oauthErr := errors.NewOAuthError(errors.ErrInvalidClient, "Invalid client_id", "")
		return "", "", nil, &oauthErr
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
			oauthErr := errors.NewOAuthError(errors.ErrInvalidRequest, "Unregistered redirect_uri", "")
			return "", "", nil, &oauthErr
		}
	} else if len(client.RedirectURIs) == 1 {
		redirectURI = client.RedirectURIs[0]
	} else {
		oauthErr := errors.NewOAuthError(errors.ErrInvalidRequest, "redirect_uri must be specified when client has multiple registered URIs", "")
		return "", "", nil, &oauthErr
	}

	return clientID, redirectURI, client, nil
}

// processAuthorization processes the authorization request
func processAuthorization(r *http.Request, validate *validator.Validate, client *auth.OAuthClientInformationFull, redirectURI string, provider server.OAuthServerProvider, w http.ResponseWriter) *errors.OAuthError {
	reqParams := parseRequestAuthorizationParams(r)
	if err := validate.Struct(reqParams); err != nil {
		oauthErr := errors.NewOAuthError(errors.ErrInvalidRequest, err.Error(), "")
		return &oauthErr
	}

	tempAuthParams := server.AuthorizationParams{
		CodeChallenge: reqParams.CodeChallenge,
	}

	if err := pkce.ValidatePKCEParams(tempAuthParams); err != nil {
		oauthErr := errors.NewOAuthError(errors.ErrInvalidRequest, err.Error(), "")
		return &oauthErr
	}

	// Validate scopes
	var requestedScopes []string
	if reqParams.Scope != "" {
		scopes := strings.Fields(reqParams.Scope)
		for _, scope := range scopes {
			if scope != "" {
				requestedScopes = append(requestedScopes, scope)
			}
		}

		if err := validateScopes(requestedScopes, client); err != nil {
			return err
		}
	}

	var resourceURL *url.URL
	if reqParams.Resource != "" {
		var err error
		resourceURL, err = url.Parse(reqParams.Resource)
		if err != nil {
			oauthErr := errors.NewOAuthError(errors.ErrInvalidRequest, "Invalid resource URL", "")
			return &oauthErr
		}
	}

	// 验证resource URL是否为绝对URL
	if !resourceURL.IsAbs() {
		oauthErr := errors.NewOAuthError(errors.ErrInvalidRequest, "Resource must be an absolute URL", "")
		return &oauthErr
	}

	authParams := server.AuthorizationParams{
		State:         reqParams.State,
		Scopes:        requestedScopes,
		RedirectURI:   redirectURI,
		CodeChallenge: reqParams.CodeChallenge,
		Resource:      resourceURL,
	}

	if err := provider.Authorize(*client, authParams, w, r); err != nil {
		oauthErr := errors.NewOAuthError(errors.ErrServerError, "Authorization failed", "")
		return &oauthErr
	}

	return nil
}

// validateScopes validates the requested scopes against client allowed scopes
func validateScopes(requestedScopes []string, client *auth.OAuthClientInformationFull) *errors.OAuthError {
	// If no scope is requested, return success directly
	if len(requestedScopes) == 0 {
		return nil
	}

	allowedScopes := make(map[string]bool)

	// Handling client-scoped configuration
	if client.Scope != nil && *client.Scope != "" {
		scopes := strings.Fields(*client.Scope)
		for _, scope := range scopes {
			if scope != "" {
				allowedScopes[scope] = true
			}
		}
	}

	// If the client does not have any scopes configured, reject all scope requests
	if len(requestedScopes) == 0 {
		oauthErr := errors.NewOAuthError(errors.ErrInvalidRequest, "Client has no registered scopes", "")
		return &oauthErr
	}

	// Verify the scope of each request
	for _, scope := range requestedScopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if !allowedScopes[scope] {
			oauthErr := errors.NewOAuthError(errors.ErrInvalidScope, fmt.Sprintf("Client was not registered with scope %s", scope), "")
			return &oauthErr
		}
	}

	return nil
}

// handleDirectError handles direct error responses (before redirect)
func handleDirectError(w http.ResponseWriter, oauthErr errors.OAuthError) {
	status := http.StatusBadRequest

	switch oauthErr.ErrorCode {
	case errors.ErrServerError.Error():
		status = http.StatusInternalServerError
	case errors.ErrInvalidClient.Error():
		status = http.StatusUnauthorized
	default:
		status = http.StatusBadRequest
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(oauthErr.ToResponseStruct())
}

// getStateFromRequest extracts state parameter from request
func getStateFromRequest(r *http.Request) string {
	if r.Method == http.MethodPost {
		return r.FormValue("state")
	}
	return r.URL.Query().Get("state")
}

// parseClientAuthorizationParams parses client authorization parameters
func parseClientAuthorizationParams(r *http.Request) ClientAuthorizationParams {
	var params ClientAuthorizationParams

	if r.Method == http.MethodPost {
		params.ClientID = strings.TrimSpace(r.FormValue("client_id"))
		params.RedirectURI = strings.TrimSpace(r.FormValue("redirect_uri"))
	} else {
		query := r.URL.Query()
		params.ClientID = strings.TrimSpace(query.Get("client_id"))
		params.RedirectURI = strings.TrimSpace(query.Get("redirect_uri"))
	}

	return params
}

// parseRequestAuthorizationParams parses request authorization parameters
func parseRequestAuthorizationParams(r *http.Request) RequestAuthorizationParams {
	var params RequestAuthorizationParams

	if r.Method == http.MethodPost {
		params.ResponseType = strings.TrimSpace(r.FormValue("response_type"))
		params.CodeChallenge = strings.TrimSpace(r.FormValue("code_challenge"))
		params.CodeChallengeMethod = strings.TrimSpace(r.FormValue("code_challenge_method"))
		params.Scope = strings.TrimSpace(r.FormValue("scope"))
		params.State = r.FormValue("state")
		params.Resource = strings.TrimSpace(r.FormValue("resource"))
	} else {
		query := r.URL.Query()
		params.ResponseType = strings.TrimSpace(query.Get("response_type"))
		params.CodeChallenge = strings.TrimSpace(query.Get("code_challenge"))
		params.CodeChallengeMethod = strings.TrimSpace(query.Get("code_challenge_method"))
		params.Scope = strings.TrimSpace(query.Get("scope"))
		params.State = query.Get("state")
		params.Resource = strings.TrimSpace(query.Get("resource"))
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
