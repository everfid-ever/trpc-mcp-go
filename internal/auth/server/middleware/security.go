package middleware

import (
	"encoding/json"
	"fmt"
	"golang.org/x/time/rate"
	"net/http"
	"strings"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/errors"
)

type SecurityMiddlewareOption struct {
	verifier server.TokenVerifier
}

func AllowedMethods(methods []string) func(http.Handler) http.Handler {
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
				json.NewEncoder(w).Encode(tooManyRequestsError.ToResponseStruct())
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ContentTypeValidationMiddleware validates Content-Type header for OAuth endpoints
// Per RFC 7009 Section 2.1, OAuth token revocation requests must use application/x-www-form-urlencoded
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
					"https://datatracker.ietf.org/doc/html/rfc7009#section-2.1",
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
					"https://datatracker.ietf.org/doc/html/rfc7009#section-2.1",
				)
				json.NewEncoder(w).Encode(invalidReqError.ToResponseStruct())
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// URLEncodedValidationMiddleware validates that Content-Type is application/x-www-form-urlencoded
// This is a convenience wrapper for OAuth 2.1 RFC 7009 compliance
func URLEncodedValidationMiddleware(allowJSONFallback bool) func(http.Handler) http.Handler {
	return ContentTypeValidationMiddleware([]string{"application/x-www-form-urlencoded"}, allowJSONFallback)
}
