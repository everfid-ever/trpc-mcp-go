package client

import (
	"context"
	"errors"
	"time"

	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
)

type ctxKey int

const (
	ctxKeyClientAuthInfo ctxKey = iota
	ctxKeyClientAuthErr
)

// ClientAuthInfo 客户端认证信息
type ClientAuthInfo struct {
	AccessToken  string
	RefreshToken *string
	ExpiresAt    *time.Time
	Scopes       []string
	Extra        map[string]interface{}
}

// WithAuthInfo 将认证信息写入context
func WithAuthInfo(ctx context.Context, info *ClientAuthInfo) context.Context {
	if info == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyClientAuthInfo, info)
}

// GetAuthInfo 从context读取认证信息
func GetAuthInfo(ctx context.Context) (*ClientAuthInfo, bool) {
	v := ctx.Value(ctxKeyClientAuthInfo)
	if v == nil {
		return nil, false
	}
	info, ok := v.(*ClientAuthInfo)
	return info, ok && info != nil
}

// WithAuthErr 将认证错误写入context
func WithAuthErr(ctx context.Context, err error) context.Context {
	if err == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyClientAuthErr, err)
}

// GetAuthErr 读取认证错误
func GetAuthErr(ctx context.Context) error {
	v := ctx.Value(ctxKeyClientAuthErr)
	if v == nil {
		return nil
	}
	if err, ok := v.(error); ok {
		return err
	}
	return errors.New("client auth error")
}

// ConvertTokensToAuthInfo 转换token为认证信息
func ConvertTokensToAuthInfo(tokens *auth.OAuthTokens) *ClientAuthInfo {
	if tokens == nil || tokens.AccessToken == "" {
		return nil
	}

	authInfo := &ClientAuthInfo{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		Scopes:       parseTokenScopes(tokens),
		Extra:        make(map[string]interface{}),
	}

	if tokens.ExpiresIn != nil {
		expiresAt := time.Now().Add(time.Duration(*tokens.ExpiresIn) * time.Second)
		authInfo.ExpiresAt = &expiresAt
	}

	return authInfo
}

// IsTokenExpired 检查token是否过期
func IsTokenExpired(authInfo *ClientAuthInfo) bool {
	if authInfo == nil {
		return true
	}

	if authInfo.ExpiresAt != nil {
		return time.Now().After(authInfo.ExpiresAt.Add(-30 * time.Second))
	}

	return false
}

func parseTokenScopes(tokens *auth.OAuthTokens) []string {
	return []string{}
}
