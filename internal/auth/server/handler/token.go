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
	"trpc.group/trpc-go/trpc-mcp-go/internal/errors"
)

// TokenHandlerOptions defines configuration options for the token endpoint
type TokenHandlerOptions struct {
	Provider  server.OAuthServerProvider `json:"provider"`
	RateLimit *TokenRateLimitConfig      `json:"rateLimit,omitempty"`
}

// TokenRateLimitConfig defines rate limit configuration
type TokenRateLimitConfig struct {
	WindowMs        int64       `json:"windowMs"` // Time window (milliseconds)
	Max             int         `json:"max"`      // Maximum number of requests
	StandardHeaders bool        `json:"standardHeaders"`
	LegacyHeaders   bool        `json:"legacyHeaders"`
	Message         interface{} `json:"message"`
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

// TokenHandler creates a token endpoint handler (native HTTP)
func TokenHandler(options TokenHandlerOptions) http.HandlerFunc {
	// Create a validator
	validate := validator.New()

	// Setting up a rate limiter
	var limiter *rate.Limiter
	if options.RateLimit != nil {
		windowDuration := time.Duration(options.RateLimit.WindowMs) * time.Millisecond
		limit := rate.Every(windowDuration / time.Duration(options.RateLimit.Max))
		limiter = rate.NewLimiter(limit, options.RateLimit.Max)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers to allow access from any origin (to support web-based MCP clients)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight OPTIONS request
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Check HTTP Method
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)

			oauthErr := errors.NewOAuthError(
				errors.ErrMethodNotAllowed,
				"Only POST method is allowed",
				"",
			)
			json.NewEncoder(w).Encode(oauthErr.ToResponseStruct())
			return
		}

		// Rate limiting is applied (unless explicitly disabled)
		if limiter != nil {
			if !limiter.Allow() {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)

				errResp := errors.NewOAuthError(errors.ErrTooManyRequests, "You have exceeded the rate limit for token requests", "")
				json.NewEncoder(w).Encode(errResp.ToResponseStruct())
				return
			}
		}

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

		// TODO 客户端认证（从上下文中获取，应该由中间件设置）
		// 从 HTTP 上下文获取客户端信息（需要通过中间件设置）
		client, ok := r.Context().Value("client").(auth.OAuthClientInformationFull)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)

			errResp := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
			json.NewEncoder(w).Encode(errResp.ToResponseStruct())
			return
		}

		switch tokenReq.GrantType {
		case "authorization_code":
			handleAuthorizationCodeGrantHTTP(w, r, validate, options.Provider, client)
		case "refresh_token":
			handleRefreshTokenGrantHTTP(w, r, validate, options.Provider, client)
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)

			errResp := errors.NewOAuthError(errors.ErrUnsupportedGrantType, "The grant type is not supported by this authorization server.", "")
			json.NewEncoder(w).Encode(errResp.ToResponseStruct())
		}
	}
}

// handleAuthorizationCodeGrantHTTP processes authorization code grant (native HTTP)
func handleAuthorizationCodeGrantHTTP(w http.ResponseWriter, r *http.Request, validate *validator.Validate, provider server.OAuthServerProvider, client auth.OAuthClientInformationFull) {
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

	// Prepare parameters - 始终传递code_verifier
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

// handleRefreshTokenGrantHTTP handles refresh token grant (native HTTP)
func handleRefreshTokenGrantHTTP(w http.ResponseWriter, r *http.Request, validate *validator.Validate, provider server.OAuthServerProvider, client auth.OAuthClientInformationFull) {
	// 解析刷新token grant请求
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
