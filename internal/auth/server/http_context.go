package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	oauthErrors "trpc.group/trpc-go/trpc-mcp-go/internal/errors"
)

type ctxKey int

const (
	ctxKeyAuthInfo ctxKey = iota
	ctxKeyAuthErr
)

// WithAuthInfo 将鉴权信息写入 context
func WithAuthInfo(ctx context.Context, info *AuthInfo) context.Context {
	if info == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyAuthInfo, info)
}

// GetAuthInfo 从 context 读取鉴权信息
func GetAuthInfo(ctx context.Context) (*AuthInfo, bool) {
	v := ctx.Value(ctxKeyAuthInfo)
	if v == nil {
		return nil, false
	}
	info, ok := v.(*AuthInfo)
	return info, ok && info != nil
}

// WithAuthErr 将鉴权阶段的错误写入 context
func WithAuthErr(ctx context.Context, err error) context.Context {
	if err == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyAuthErr, err)
}

// GetAuthErr 读取鉴权阶段的错误
func GetAuthErr(ctx context.Context) error {
	v := ctx.Value(ctxKeyAuthErr)
	if v == nil {
		return nil
	}
	if err, ok := v.(error); ok {
		return err
	}
	return errors.New("auth err")
}

// WriteAuthChallenge 写入认证挑战响应
func WriteAuthChallenge(w http.ResponseWriter, status int, code, desc, scope string) {
	val := fmt.Sprintf(`Bearer realm="mcp", error="%s", error_description="%s"`, code, desc)
	if scope != "" {
		val += fmt.Sprintf(`, scope="%s"`, scope)
	}
	w.Header().Set("WWW-Authenticate", val)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	http.Error(w, http.StatusText(status), status)
}

// DetermineAuthError 根据错误类型确定 HTTP 状态码和错误码
func DetermineAuthError(err error) (int, string, string) {
	switch {
	case errors.Is(err, oauthErrors.ErrInsufficientScope):
		return http.StatusForbidden, "insufficient_scope", "Token lacks required scope"
	case errors.Is(err, oauthErrors.ErrInvalidRequest):
		return http.StatusBadRequest, "invalid_request", "Missing or malformed authorization"
	case errors.Is(err, oauthErrors.ErrInvalidClient):
		return http.StatusUnauthorized, "invalid_client", "Client authentication failed"
	case errors.Is(err, oauthErrors.ErrInvalidToken):
		return http.StatusUnauthorized, "invalid_token", "The access token is invalid or expired"
	default:
		// 兜底仍可保留字符串判断或直接归为 invalid_token
		return http.StatusUnauthorized, "invalid_token", "Token verification failed"
	}
}
