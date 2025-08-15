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
