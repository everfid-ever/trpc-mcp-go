package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"trpc.group/trpc-go/trpc-mcp-go/internal/errors"
)

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
				fmt.Sprintf("The method %s is not allowed for this endpoint", r.Method),
				"", // 可选的错误URI
			)

			// 转换为响应结构并编码
			_ = json.NewEncoder(w).Encode(oauthErr.ToResponseStruct())
		})
	}
}
