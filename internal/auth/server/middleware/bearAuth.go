package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/errors"
)

// BearerAuthMiddlewareOptions 定义Bearer认证中间件的配置选项。
// Defines configuration options for the Bearer authentication middleware.
type BearerAuthMiddlewareOptions struct {
	// Verifier 用于验证令牌的提供者。
	// Token verifier provider.
	Verifier server.TokenVerifier

	// RequiredScopes 可选的权限范围，验证令牌必须包含所有指定范围。
	// Optional scopes that the token must have.
	RequiredScopes []string

	// ResourceMetadataURL 可选的资源元数据URL，包含在WWW-Authenticate头中。
	// Optional resource metadata URL to include in WWW-Authenticate header.
	ResourceMetadataURL *string
}

// RequireBearerAuth 返回一个HTTP中间件，验证请求中的Bearer令牌。
// Returns an HTTP middleware that validates Bearer tokens in the request.
func RequireBearerAuth(options BearerAuthMiddlewareOptions) func(handler http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

			// 处理错误并设置响应函数
			setErrorResponse := func(w http.ResponseWriter, err errors.OAuthError, statusCode int) {
				wwwAuthValue := fmt.Sprintf(`Bearer error="%s", error_description="%s"`, err.ErrorCode, err.Message)
				if options.ResourceMetadataURL != nil {
					wwwAuthValue += fmt.Sprintf(`, resource_metadata="%s"`, *options.ResourceMetadataURL)
				}
				w.Header().Set("WWW-Authenticate", wwwAuthValue)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(statusCode)
				json.NewEncoder(w).Encode(err.ToResponseStruct())
			}

			// 获取Authorization头
			authHeader := req.Header.Get("Authorization")
			if authHeader == "" {
				setErrorResponse(w, errors.NewOAuthError(errors.ErrInvalidToken, "Missing Authorization header", ""), http.StatusUnauthorized)
				return
			}

			// 解析Authorization头
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" || parts[1] == "" {
				setErrorResponse(w, errors.NewOAuthError(errors.ErrInvalidToken, "Invalid Authorization header format, expected 'Bearer TOKEN'", ""), http.StatusUnauthorized)
				return
			}
			token := parts[1]

			// 验证令牌
			authInfo, err := options.Verifier.VerifyAccessToken(token)
			if err != nil {
				if oauthErr, ok := err.(errors.OAuthError); ok {
					switch oauthErr.ErrorCode {
					case errors.ErrInvalidToken.Error():
						setErrorResponse(w, oauthErr, http.StatusUnauthorized)
					case errors.ErrInsufficientScope.Error():
						setErrorResponse(w, oauthErr, http.StatusForbidden)
					case errors.ErrServerError.Error():
						setErrorResponse(w, oauthErr, http.StatusInternalServerError)
					default:
						setErrorResponse(w, oauthErr, http.StatusBadRequest)
					}
				} else {
					serverErr := errors.NewOAuthError(errors.ErrServerError, "Internal Server Error", "")
					setErrorResponse(w, serverErr, http.StatusInternalServerError)
				}
				return
			}

			// 遍历检查权限范围
			if len(options.RequiredScopes) > 0 {
				for _, scope := range options.RequiredScopes {
					found := false
					for _, tokenScope := range authInfo.Scopes {
						if tokenScope == scope {
							found = true
							break
						}
					}
					if !found {
						setErrorResponse(w, errors.NewOAuthError(errors.ErrInsufficientScope, "Insufficient scope", ""), http.StatusForbidden)
						return
					}
				}
			}

			// 检查令牌过期时间
			if authInfo.ExpiresAt == nil || *authInfo.ExpiresAt == 0 {
				setErrorResponse(w, errors.NewOAuthError(errors.ErrInvalidToken, "Token has no expiration time", ""), http.StatusUnauthorized)
				return
			}
			if *authInfo.ExpiresAt < time.Now().Unix() {
				setErrorResponse(w, errors.NewOAuthError(errors.ErrInvalidToken, "Token has expired", ""), http.StatusUnauthorized)
				return
			}

			// 将authInfo添加到请求上下文,对应的key为authInfoKeyType{}
			ctx := context.WithValue(req.Context(), authInfoKeyType{}, authInfo)
			req = req.WithContext(ctx)

			next.ServeHTTP(w, req)
		})
	}
}

// authInfoKey 用于标识存储AuthInfo的上下文键
type authInfoKeyType struct{}
