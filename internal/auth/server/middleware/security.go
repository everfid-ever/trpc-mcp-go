package middleware

import (
	"net/http"
	"strings"
	mcp "trpc.group/trpc-go/trpc-mcp-go"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/errors"
)

type SecurityMiddlewareOption struct {
	verifier server.TokenVerifier
}

func AllowedMethods(allowedMethods []string, req mcp.JSONRPCRequest) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, method := range allowedMethods {
				if r.Method == method {
					next.ServeHTTP(w, r)
					return
				}
			}
			err := errors.NewOAuthError(errors.ErrMethodNotAllowed, "method not allowed", "")
			w.Header().Set("Allow", strings.Join(allowedMethods, ", "))
			w.WriteHeader(http.StatusMethodNotAllowed)
			mcp.MakeJSONRPCErrorResponse(req.ID, mcp.ErrCodeInvalidParams, err.Error(), err.ToResponseStruct())
		})
	}
}
