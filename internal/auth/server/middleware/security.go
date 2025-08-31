package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/time/rate"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/errors"
)

type SecurityMiddlewareOption struct {
	verifier server.TokenVerifier
}

// Authorizer define a unified authorization decision interface
type Authorizer interface {
	Authorize(authInfo server.AuthInfo, resource string, action string) error
}

// ScopePermissionMapper is responsible for mapping scopes to internal permissions
type ScopePermissionMapper interface {
	MapScopes(scopes []string) []string
}

type DefaultScopeMapper struct {
	Mapping map[string][]string
}

func (m *DefaultScopeMapper) MapScopes(scopes []string) []string {
	var perms []string
	for _, scope := range scopes {
		if mapped, ok := m.Mapping[scope]; ok {
			perms = append(perms, mapped...)
		}
	}
	return perms
}

type PolicyAuthorizer struct {
	ScopeMapper ScopePermissionMapper
}

func (a *PolicyAuthorizer) Authorize(authInfo server.AuthInfo, resource string, action string) error {
	// 将 scope 转换为内部权限
	perms := a.ScopeMapper.MapScopes(authInfo.Scopes)

	// 构建所需的目标权限
	required := fmt.Sprintf("%s:%s", resource, action) // e.g. urn:mcp:workspace:xyz:read

	// 检查是否包含
	for _, p := range perms {
		if p == required {
			return nil
		}
	}

	return errors.NewOAuthError(errors.ErrInsufficientScope,
		fmt.Sprintf("Missing permission %s", required), "")
}

// responseWriterWithStatus 包装 http.ResponseWriter 用于捕获状态码
type responseWriterWithStatus struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriterWithStatus) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func CorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 获取请求的 Origin
		origin := r.Header.Get("Origin")
		if origin == "" {
			// 非跨域请求
			next.ServeHTTP(w, r)
			return
		}

		// 设置默认的 CORS 头
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE")

		// 处理预检请求
		if r.Method == http.MethodOptions {
			// Express 默认返回 204 No Content，并设置 Content-Length: 0
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// 调用下一个处理器（实际请求不设置 Allow-Headers）
		next.ServeHTTP(w, r)
	})
}

// RateLimitMiddleware applies rate limiting
func RateLimitMiddleware(limiter *rate.Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow() {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)

				tooManyRequestsError := errors.NewOAuthError(
					errors.ErrTooManyRequests,
					"You have exceeded the rate limit for token revocation requests",
					"",
				)
				_ = json.NewEncoder(w).Encode(tooManyRequestsError.ToResponseStruct())

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ContentTypeValidationMiddleware validates Content-Type header for OAuth endpoints
// This is the base validation middleware that other content type middlewares can build upon
func ContentTypeValidationMiddleware(allowedTypes []string, allowJSONFallback bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			contentType := r.Header.Get("Content-Type")

			// Content-Type header is required
			if contentType == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)

				invalidReqError := errors.NewOAuthError(
					errors.ErrInvalidRequest,
					"Content-Type header is required",
					"",
				)
				_ = json.NewEncoder(w).Encode(invalidReqError.ToResponseStruct())
				return
			}

			// Check if content type is allowed
			var isValid bool
			for _, allowedType := range allowedTypes {
				if strings.HasPrefix(contentType, allowedType) {
					isValid = true
					break
				}
			}

			// Special handling for JSON fallback
			if !isValid && allowJSONFallback && strings.HasPrefix(contentType, "application/json") {
				isValid = true
			}

			if !isValid {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)

				errorMsg := fmt.Sprintf("Content-Type must be one of: %s", strings.Join(allowedTypes, ", "))
				if allowJSONFallback {
					errorMsg = fmt.Sprintf("Content-Type must be %s (preferred) or application/json", allowedTypes[0])
				}

				invalidReqError := errors.NewOAuthError(
					errors.ErrInvalidRequest,
					errorMsg,
					"",
				)
				_ = json.NewEncoder(w).Encode(invalidReqError.ToResponseStruct())
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// URLEncodedValidationMiddleware validates that Content-Type is application/x-www-form-urlencoded
// This is a convenience wrapper for OAuth 2.1 RFC 7009 compliance (token revocation)
func URLEncodedValidationMiddleware(allowJSONFallback bool) func(http.Handler) http.Handler {
	return ContentTypeValidationMiddleware([]string{"application/x-www-form-urlencoded"}, allowJSONFallback)
}

// JSONValidationMiddleware validates that Content-Type is application/json
// This is a convenience wrapper for endpoints that only accept JSON (like client registration)
func JSONValidationMiddleware() func(http.Handler) http.Handler {
	return ContentTypeValidationMiddleware([]string{"application/json"}, false)
}

func AuthorizationMiddleware(authorizer Authorizer, resource string, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authInfo, ok := GetAuthInfo(r.Context())
			if !ok {
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="No authentication info found"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// 执行授权判定
			err := authorizer.Authorize(authInfo, resource, action)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(err.(errors.OAuthError).ToResponseStruct())

				// 提取 subject
				subject := extractSubject(authInfo)

				return
			}

			// 提取 subject
			subject := extractSubject(authInfo)

			next.ServeHTTP(w, r)
		})
	}
}
