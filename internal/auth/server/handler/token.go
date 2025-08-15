package handler

import (
	"encoding/json"
	"github.com/go-playground/validator/v10"
	"golang.org/x/time/rate"
	"net/http"
	"net/url"
	"strings"
	"time"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/middleware"
	"trpc.group/trpc-go/trpc-mcp-go/internal/errors"
)

// TokenHandlerOptions defines configuration options for the token endpoint
type TokenHandlerOptions struct {
	Provider  server.OAuthServerProvider `json:"provider"`
	RateLimit *rate.Limiter              `json:"rateLimit,omitempty"` // 使用标准的 rate.Limiter
}

// TokenRequest defines basic token request structure
type TokenRequest struct {
	GrantType string `json:"grant_type" validate:"required"`
}

// AuthorizationCodeGrant defines authorization code grant request
type AuthorizationCodeGrant struct {
	Code         string  `json:"code" validate:"required"`
	CodeVerifier string  `json:"code_verifier" validate:"required"`
	RedirectURI  *string `json:"redirect_uri,omitempty"`
	Resource     *string `json:"resource,omitempty" validate:"omitempty,url"`
}

// RefreshTokenGrant defines refresh token grant request
type RefreshTokenGrant struct {
	RefreshToken string  `json:"refresh_token" validate:"required"`
	Scope        *string `json:"scope,omitempty"`
	Resource     *string `json:"resource,omitempty" validate:"omitempty,url"`
}

// TokenHandler creates a token endpoint handler with full middleware stack
func TokenHandler(options TokenHandlerOptions) http.HandlerFunc {
	// Create the core handler logic
	coreHandler := createTokenCoreHandler(options)

	// Apply middlewares in order
	var handler http.Handler = coreHandler

	// Apply client authentication middleware
	handler = middleware.AuthenticateClient(middleware.ClientAuthenticationMiddlewareOptions{
		ClientsStore: options.Provider.ClientsStore(),
	})(handler)

	// Apply rate limiting middleware
	limiter := options.RateLimit
	if limiter == nil {
		// Default rate limiting: 60 requests per minute
		limiter = rate.NewLimiter(rate.Every(time.Second), 60)
	}
	handler = middleware.RateLimitMiddleware(limiter)(handler)

	// Apply method restriction middleware (only POST allowed)
	handler = middleware.AllowedMethods([]string{"POST"})(handler)

	// Apply CORS middleware
	handler = middleware.CorsMiddleware(handler)

	// Convert http.Handler to http.HandlerFunc
	return func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}
}

// createTokenCoreHandler creates the core token handler logic shared between both versions
func createTokenCoreHandler(options TokenHandlerOptions) http.HandlerFunc {
	// Create a validator
	validate := validator.New()

	return func(w http.ResponseWriter, r *http.Request) {
		// Set cache-control headers
		w.Header().Set("Cache-Control", "no-store")

		// Parsing form data
		if err := r.ParseForm(); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)

			errResp := errors.NewOAuthError(errors.ErrInvalidRequest, "Failed to parse form data", "")
			json.NewEncoder(w).Encode(errResp.ToResponseStruct())
			return
		}

		// Verify basic token request
		tokenReq := TokenRequest{
			GrantType: r.FormValue("grant_type"),
		}

		if err := validate.Struct(tokenReq); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)

			errResp := errors.NewOAuthError(errors.ErrInvalidRequest, err.Error(), "")
			json.NewEncoder(w).Encode(errResp.ToResponseStruct())
			return
		}

		// 使用 AuthenticateClient 中间件设置的客户端信息
		client, ok := middleware.GetAuthenticatedClient(r)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			errResp := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
			json.NewEncoder(w).Encode(errResp.ToResponseStruct())
			return
		}

		switch tokenReq.GrantType {
		case "authorization_code":
			handleAuthorizationCodeGrant(w, r, validate, options.Provider, *client)
		case "refresh_token":
			handleRefreshTokenGrant(w, r, validate, options.Provider, *client)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)

			errResp := errors.NewOAuthError(errors.ErrUnsupportedGrantType, "The grant type is not supported by this authorization server.", "")
			json.NewEncoder(w).Encode(errResp.ToResponseStruct())
		}
	}
}

// handleAuthorizationCodeGrant processes authorization code grant
func handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, validate *validator.Validate, provider server.OAuthServerProvider, client auth.OAuthClientInformationFull) {
	// Parsing the authorization code grant request
	var redirectURI *string
	if uri := r.FormValue("redirect_uri"); uri != "" {
		redirectURI = &uri
	}

	var resource *string
	if res := r.FormValue("resource"); res != "" {
		resource = &res
	}

	grant := AuthorizationCodeGrant{
		Code:         r.FormValue("code"),
		CodeVerifier: r.FormValue("code_verifier"),
		RedirectURI:  redirectURI,
		Resource:     resource,
	}

	if err := validate.Struct(grant); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		errResp := errors.NewOAuthError(errors.ErrInvalidRequest, err.Error(), "")
		json.NewEncoder(w).Encode(errResp.ToResponseStruct())
		return
	}

	// Prepare parameters - 始终传递 code_verifier
	codeVerifier := &grant.CodeVerifier

	var resourceURL *url.URL
	if grant.Resource != nil {
		var err error
		resourceURL, err = url.Parse(*grant.Resource)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)

			errResp := errors.NewOAuthError(errors.ErrInvalidRequest, "Invalid resource URL", "")
			json.NewEncoder(w).Encode(errResp.ToResponseStruct())
			return
		}
	}

	// Exchange the authorization code for a token
	tokens, err := provider.ExchangeAuthorizationCode(
		client,
		grant.Code,
		codeVerifier,
		grant.RedirectURI,
		resourceURL,
	)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")

		// Return an appropriate OAuth error response based on the error type
		switch {
		case err == errors.ErrInvalidParams || err == errors.ErrMissingParams:
			w.WriteHeader(http.StatusBadRequest)
			errResp := errors.NewOAuthError(errors.ErrInvalidRequest, err.Error(), "")
			json.NewEncoder(w).Encode(errResp.ToResponseStruct())
		case err == errors.ErrInvalidJSONRPCParams:
			w.WriteHeader(http.StatusBadRequest)
			errResp := errors.NewOAuthError(errors.ErrInvalidGrant, err.Error(), "")
			json.NewEncoder(w).Encode(errResp.ToResponseStruct())
		default:
			w.WriteHeader(http.StatusInternalServerError)
			errResp := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
			json.NewEncoder(w).Encode(errResp.ToResponseStruct())
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokens)
}

// handleRefreshTokenGrant handles refresh token grant
func handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, validate *validator.Validate, provider server.OAuthServerProvider, client auth.OAuthClientInformationFull) {
	// 解析刷新 token grant 请求
	var scope *string
	if s := r.FormValue("scope"); s != "" {
		scope = &s
	}

	var resource *string
	if res := r.FormValue("resource"); res != "" {
		resource = &res
	}

	grant := RefreshTokenGrant{
		RefreshToken: r.FormValue("refresh_token"),
		Scope:        scope,
		Resource:     resource,
	}

	if err := validate.Struct(grant); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		errResp := errors.NewOAuthError(errors.ErrInvalidRequest, err.Error(), "")
		json.NewEncoder(w).Encode(errResp.ToResponseStruct())
		return
	}

	// Handle scopes
	var scopes []string
	if grant.Scope != nil {
		scopes = strings.Split(*grant.Scope, " ")
	}

	// Handle resource URL
	var resourceURL *url.URL
	if grant.Resource != nil {
		var err error
		resourceURL, err = url.Parse(*grant.Resource)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)

			errResp := errors.NewOAuthError(errors.ErrInvalidRequest, "Invalid resource URL", "")
			json.NewEncoder(w).Encode(errResp.ToResponseStruct())
			return
		}
	}

	// Swap refresh token
	tokens, err := provider.ExchangeRefreshToken(client, grant.RefreshToken, scopes, resourceURL)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case err == errors.ErrInvalidParams || err == errors.ErrMissingParams:
			w.WriteHeader(http.StatusBadRequest)
			errResp := errors.NewOAuthError(errors.ErrInvalidRequest, err.Error(), "")
			json.NewEncoder(w).Encode(errResp.ToResponseStruct())
		case err == errors.ErrInvalidJSONRPCParams:
			w.WriteHeader(http.StatusBadRequest)
			errResp := errors.NewOAuthError(errors.ErrInvalidGrant, err.Error(), "")
			json.NewEncoder(w).Encode(errResp.ToResponseStruct())
		default:
			w.WriteHeader(http.StatusInternalServerError)
			errResp := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
			json.NewEncoder(w).Encode(errResp.ToResponseStruct())
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tokens)
}
