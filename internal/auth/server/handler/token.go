package handler

import (
	"github.com/gin-gonic/gin"
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

// TODO PKCE验证函数 - 简化的实现，实际应该使用crypto包
func verifyChallenge(codeVerifier, codeChallenge string) bool {
	// 这里应该实现实际的PKCE验证逻辑
	// 简化实现，实际应该根据challenge method进行SHA256等计算
	return len(codeVerifier) >= 43 && len(codeVerifier) <= 128
}

// TokenHandler creates a token endpoint handler
func TokenHandler(options TokenHandlerOptions) gin.HandlerFunc {
	// 创建验证器
	validate := validator.New()

	// Setting up a rate limiter
	var limiter *rate.Limiter
	if options.RateLimit != nil {
		windowDuration := time.Duration(options.RateLimit.WindowMs) * time.Millisecond
		limit := rate.Every(windowDuration / time.Duration(options.RateLimit.Max))
		limiter = rate.NewLimiter(limit, options.RateLimit.Max)
	}

	return func(c *gin.Context) {
		// Set CORS headers to allow access from any origin (to support web-based MCP clients)
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "POST")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Check HTTP Method
		if c.Request.Method != http.MethodPost {
			c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "method_not_allowed"})
			return
		}

		// Rate limiting is applied (unless explicitly disabled)
		if limiter != nil {
			if !limiter.Allow() {
				errResp := errors.NewOAuthError(errors.ErrTooManyRequests, "You have exceeded the rate limit for token requests", "")
				c.JSON(http.StatusTooManyRequests, errResp.ToResponseStruct())
				return
			}
		}

		// Set cache-control headers
		c.Header("Cache-Control", "no-store")

		// Parsing form data
		if err := c.Request.ParseForm(); err != nil {
			errResp := errors.NewOAuthError(errors.ErrInvalidRequest, "Failed to parse form data", "")
			c.JSON(http.StatusBadRequest, errResp.ToResponseStruct())
			return
		}

		// Verify basic token request
		tokenReq := TokenRequest{
			GrantType: c.Request.FormValue("grant_type"),
		}

		if err := validate.Struct(tokenReq); err != nil {
			errResp := errors.NewOAuthError(errors.ErrInvalidRequest, err.Error(), "")
			c.JSON(http.StatusBadRequest, errResp.ToResponseStruct())
			return
		}

		// TODO 客户端认证（从上下文中获取，应该由中间件设置）
		clientInterface, exists := c.Get("client")
		if !exists {
			errResp := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
			c.JSON(http.StatusInternalServerError, errResp.ToResponseStruct())
			return
		}

		client, ok := clientInterface.(auth.OAuthClientInformationFull)
		if !ok {
			errorResponse := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
			c.JSON(http.StatusInternalServerError, errorResponse)
			return
		}

		switch tokenReq.GrantType {
		case "authorization_code":
			handleAuthorizationCodeGrant(c, validate, options.Provider, client)
		case "refresh_token":
			handleRefreshTokenGrant(c, validate, options.Provider, client)
		default:
			errResp := errors.NewOAuthError(errors.ErrUnsupportedGrantType, "The grant type is not supported by this authorization server.", "")
			c.JSON(http.StatusBadRequest, errResp.ToResponseStruct())
		}
	}
}

// handleAuthorizationCodeGrant processes authorization code grant
func handleAuthorizationCodeGrant(c *gin.Context, validate *validator.Validate, provider server.OAuthServerProvider, client auth.OAuthClientInformationFull) {
	// 解析授权码grant请求
	var redirectURI *string
	if uri := c.Request.FormValue("redirect_uri"); uri != "" {
		redirectURI = &uri
	}

	var resource *string
	if res := c.Request.FormValue("resource"); res != "" {
		resource = &res
	}

	grant := AuthorizationCodeGrant{
		Code:         c.Request.FormValue("code"),
		CodeVerifier: c.Request.FormValue("code_verifier"),
		RedirectURI:  redirectURI,
		Resource:     resource,
	}

	if err := validate.Struct(grant); err != nil {
		errResp := errors.NewOAuthError(errors.ErrInvalidRequest, err.Error(), "")
		c.JSON(http.StatusBadRequest, errResp.ToResponseStruct())
		return
	}

	// 检查是否跳过本地PKCE验证
	skipLocalPkceValidation := false
	if skipper, ok := provider.(interface{ SkipLocalPkceValidation() bool }); ok {
		skipLocalPkceValidation = skipper.SkipLocalPkceValidation()
	}

	// 执行本地PKCE验证（除非明确跳过）
	if !skipLocalPkceValidation {
		codeChallenge, err := provider.ChallengeForAuthorizationCode(client, grant.Code)
		if err != nil {
			errResp := errors.NewOAuthError(errors.ErrInvalidGrant, "Invalid authorization code", "")
			c.JSON(http.StatusBadRequest, errResp.ToResponseStruct())
			return
		}

		if !verifyChallenge(grant.CodeVerifier, codeChallenge) {
			errResp := errors.NewOAuthError(errors.ErrInvalidGrant, "code_verifier does not match the challenge", "")
			c.JSON(http.StatusBadRequest, errResp.ToResponseStruct())
			return
		}
	}

	// Prepare parameters
	var codeVerifier *string
	if skipLocalPkceValidation {
		codeVerifier = &grant.CodeVerifier
	}

	var resourceURL *url.URL
	if grant.Resource != nil {
		var err error
		resourceURL, err = url.Parse(*grant.Resource)
		if err != nil {
			errResp := errors.NewOAuthError(errors.ErrInvalidRequest, "Invalid resource URL", "")
			c.JSON(http.StatusBadRequest, errResp.ToResponseStruct())
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
		// Return an appropriate OAuth error response based on the error type
		switch {
		case err == errors.ErrInvalidParams || err == errors.ErrMissingParams:
			errResp := errors.NewOAuthError(errors.ErrInvalidRequest, err.Error(), "")
			c.JSON(http.StatusBadRequest, errResp.ToResponseStruct())
		case err == errors.ErrInvalidJSONRPCParams:
			errResp := errors.NewOAuthError(errors.ErrInvalidGrant, err.Error(), "")
			c.JSON(http.StatusBadRequest, errResp.ToResponseStruct())
		default:
			errResp := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
			c.JSON(http.StatusInternalServerError, errResp.ToResponseStruct())
		}
		return
	}

	c.JSON(http.StatusOK, tokens)
}

// handleRefreshTokenGrant handles refresh token grant
func handleRefreshTokenGrant(c *gin.Context, validate *validator.Validate, provider server.OAuthServerProvider, client auth.OAuthClientInformationFull) {
	// 解析刷新token grant请求
	var scope *string
	if s := c.Request.FormValue("scope"); s != "" {
		scope = &s
	}

	var resource *string
	if res := c.Request.FormValue("resource"); res != "" {
		resource = &res
	}

	grant := RefreshTokenGrant{
		RefreshToken: c.Request.FormValue("refresh_token"),
		Scope:        scope,
		Resource:     resource,
	}

	if err := validate.Struct(grant); err != nil {
		errResp := errors.NewOAuthError(errors.ErrInvalidRequest, err.Error(), "")
		c.JSON(http.StatusBadRequest, errResp.ToResponseStruct())
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
			errResp := errors.NewOAuthError(errors.ErrInvalidRequest, "Invalid resource URL", "")
			c.JSON(http.StatusBadRequest, errResp.ToResponseStruct())
			return
		}
	}

	// Swap refresh token
	tokens, err := provider.ExchangeRefreshToken(client, grant.RefreshToken, scopes, resourceURL)

	if err != nil {
		switch {
		case err == errors.ErrInvalidParams || err == errors.ErrMissingParams:
			errResp := errors.NewOAuthError(errors.ErrInvalidRequest, err.Error(), "")
			c.JSON(http.StatusBadRequest, errResp.ToResponseStruct())
		case err == errors.ErrInvalidJSONRPCParams:
			errResp := errors.NewOAuthError(errors.ErrInvalidGrant, err.Error(), "")
			c.JSON(http.StatusBadRequest, errResp.ToResponseStruct())
		default:
			errResp := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
			c.JSON(http.StatusInternalServerError, errResp.ToResponseStruct())
		}
		return
	}

	c.JSON(http.StatusOK, tokens)
}
