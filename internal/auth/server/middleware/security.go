package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/time/rate"
	"net/http"
	"strings"
	"time"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/errors"
)

type SecurityMiddlewareOption struct {
	verifier   server.TokenVerifier
	OnDecision OnDecision
}

// Authorizer define a unified authorization decision interface
type Authorizer interface {
	Authorize(authInfo *server.AuthInfo, resource string, action string) error
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

// Decision defines audit decision-making structure
type Decision struct {
	Allowed   bool
	Reason    string
	ClientID  string
	Subject   string
	Scopes    []string
	Resource  string
	Action    string
	TraceID   string
	Timestamp time.Time
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

type OnDecision func(Decision)

func AllowedMethods(methods []string, onDecision OnDecision) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, method := range methods {
				if r.Method == method {
					next.ServeHTTP(w, r)
					return
				}
			}

			w.Header().Set("Allow", strings.Join(methods, ", "))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)

			// 创建OAuth错误
			oauthErr := errors.NewOAuthError(
				errors.ErrMethodNotAllowed,
				fmt.Sprintf("HTTP method %s not allowed", r.Method),
				"", // 可选的错误URI
			)

			// 转换为响应结构并编码
			json.NewEncoder(w).Encode(oauthErr.ToResponseStruct())

			if onDecision != nil {
				onDecision(Decision{
					Allowed:   false,
					Reason:    "method not allowed",
					Resource:  r.URL.Path,
					Action:    r.Method,
					TraceID:   r.Header.Get("X-Request-ID"),
					Timestamp: time.Now(),
				})
			}
		})
	}
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
func RateLimitMiddleware(limiter *rate.Limiter, onDecision OnDecision) func(http.Handler) http.Handler {
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
				json.NewEncoder(w).Encode(tooManyRequestsError.ToResponseStruct())

				if onDecision != nil {
					onDecision(Decision{
						Allowed:   false,
						Reason:    "rate limit exceeded",
						Resource:  r.URL.Path,
						Action:    r.Method,
						TraceID:   r.Header.Get("X-Request-ID"),
						Timestamp: time.Now(),
					})
				}
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
				json.NewEncoder(w).Encode(invalidReqError.ToResponseStruct())
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
				json.NewEncoder(w).Encode(invalidReqError.ToResponseStruct())
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

func AuditMiddleware(onDecision OnDecision) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 包装 ResponseWriter 以获取状态码
			rw := &responseWriterWithStatus{ResponseWriter: w, statusCode: http.StatusOK}

			start := time.Now()
			next.ServeHTTP(rw, r)
			duration := time.Since(start)

			// 构建审计事件
			if onDecision != nil {
				onDecision(Decision{
					Allowed:   rw.statusCode < 400, // 状态码 <400 认为成功
					Reason:    http.StatusText(rw.statusCode),
					Resource:  r.URL.Path,
					Action:    r.Method,
					TraceID:   r.Header.Get("X-Request-ID"), // 可选，追踪 ID
					Timestamp: time.Now(),
				})
			}

			// 可选：打印调试日志
			fmt.Printf("[AUDIT] %s %s -> %d (%v)\n", r.Method, r.URL.Path, rw.statusCode, duration)
		})
	}
}

func AuthorizationMiddleware(authorizer Authorizer, resource string, action string, onDecision OnDecision) func(http.Handler) http.Handler {
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
				json.NewEncoder(w).Encode(err.(errors.OAuthError).ToResponseStruct())

				if onDecision != nil {
					onDecision(Decision{
						Allowed:   false,
						Reason:    err.Error(),
						ClientID:  authInfo.ClientID,
						Subject:   authInfo.Subject,
						Scopes:    authInfo.Scopes,
						Resource:  resource,
						Action:    action,
						TraceID:   r.Header.Get("X-Request-ID"),
						Timestamp: time.Now(),
					})
				}
				return
			}

			// 授权成功
			if onDecision != nil {
				onDecision(Decision{
					Allowed:   true,
					Reason:    "authorized",
					ClientID:  authInfo.ClientID,
					Subject:   authInfo.Subject,
					Scopes:    authInfo.Scopes,
					Resource:  resource,
					Action:    action,
					TraceID:   r.Header.Get("X-Request-ID"),
					Timestamp: time.Now(),
				})
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetAuthInfo 从请求上下文中提取 AuthInfo
func GetAuthInfo(ctx context.Context) (*server.AuthInfo, bool) {
	authInfo, ok := ctx.Value(authInfoKeyType{}).(*server.AuthInfo)
	return authInfo, ok
}
