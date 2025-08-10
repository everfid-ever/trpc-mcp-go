package token

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
	errors2 "trpc.group/trpc-go/trpc-mcp-go/internal/auth/errors"
)

// VerificationResult 验证结果
type VerificationResult struct {
	Valid        bool          `json:"valid"`
	TokenInfo    *TokenInfo    `json:"token_info,omitempty"`
	Claims       jwt.MapClaims `json:"claims,omitempty"`
	Method       string        `json:"method"` // "local" or "remote"
	Issuer       string        `json:"issuer"`
	Error        error         `json:"error,omitempty"`
	CacheHit     bool          `json:"cache_hit"`
	VerifiedAt   time.Time     `json:"verified_at"`
	ResponseTime time.Duration `json:"response_time"`
}

// VerifyToken 验证JWT令牌
func (v *TokenVerifier) VerifyToken(ctx context.Context, tokenString string) (*VerificationResult, error) {
	start := time.Now()

	v.metrics.mu.Lock()
	v.metrics.TotalVerifications++
	v.metrics.mu.Unlock()

	// 根据策略选择验证方法
	var result *VerificationResult
	var err error

	switch v.config.VerificationStrategy {
	case LocalFirst:
		result, err = v.verifyLocalFirst(ctx, tokenString)
	case RemoteFirst:
		result, err = v.verifyRemoteFirst(ctx, tokenString)
	case LocalOnly:
		result, err = v.verifyLocal(ctx, tokenString)
	case RemoteOnly:
		result, err = v.verifyRemote(ctx, tokenString)
	case Hybrid:
		result, err = v.verifyHybrid(ctx, tokenString)
	default:
		result, err = v.verifyLocalFirst(ctx, tokenString)
	}

	if result != nil {
		result.ResponseTime = time.Since(start)
		result.VerifiedAt = time.Now()
	}

	if err != nil {
		v.metrics.mu.Lock()
		v.metrics.VerificationErrors++
		v.metrics.mu.Unlock()
	}

	return result, err
}

// VerifyTokenWithScopes 验证令牌并检查作用域
func (v *TokenVerifier) VerifyTokenWithScopes(ctx context.Context, tokenString string, requiredScopes []string) (*VerificationResult, error) {
	result, err := v.VerifyToken(ctx, tokenString)
	if err != nil {
		return result, err
	}

	if !result.Valid {
		return result, nil
	}

	// 验证作用域
	if len(requiredScopes) > 0 {
		if !v.hasRequiredScopes(result.TokenInfo.Scopes, requiredScopes) {
			result.Valid = false
			result.Error = errors2.ErrInsufficientScope
		}
	}

	return result, nil
}

// verifyLocalFirst 优先本地验证
func (v *TokenVerifier) verifyLocalFirst(ctx context.Context, tokenString string) (*VerificationResult, error) {
	if !v.config.LocalVerification.Enabled {
		return v.verifyRemote(ctx, tokenString)
	}

	result, err := v.verifyLocal(ctx, tokenString)
	if err == nil && result.Valid {
		return result, nil
	}

	// 本地验证失败，尝试远程验证
	if v.config.RemoteVerification.Enabled && v.config.RemoteVerification.FallbackEnabled {
		remoteResult, remoteErr := v.verifyRemote(ctx, tokenString)
		if remoteErr == nil {
			return remoteResult, nil
		}
	}

	return result, err
}

// verifyRemoteFirst 优先远程验证
func (v *TokenVerifier) verifyRemoteFirst(ctx context.Context, tokenString string) (*VerificationResult, error) {
	if !v.config.RemoteVerification.Enabled {
		return v.verifyLocal(ctx, tokenString)
	}

	result, err := v.verifyRemote(ctx, tokenString)
	if err == nil && result.Valid {
		return result, nil
	}

	// 远程验证失败，尝试本地验证
	if v.config.LocalVerification.Enabled {
		localResult, localErr := v.verifyLocal(ctx, tokenString)
		if localErr == nil {
			return localResult, nil
		}
	}

	return result, err
}

// verifyLocal 本地JWT验证
func (v *TokenVerifier) verifyLocal(ctx context.Context, tokenString string) (*VerificationResult, error) {
	v.metrics.mu.Lock()
	v.metrics.LocalVerifications++
	v.metrics.mu.Unlock()

	// 解析JWT头部获取发行者和密钥ID
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// 获取发行者
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, fmt.Errorf("invalid claims type")
		}

		issuer, ok := claims["iss"].(string)
		if !ok {
			return nil, fmt.Errorf("missing issuer claim")
		}

		// 获取密钥ID
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing key ID in header")
		}

		// 验证算法
		alg := token.Header["alg"].(string)
		if !v.isSupportedAlgorithm(alg) {
			return nil, fmt.Errorf("unsupported algorithm: %s", alg)
		}

		// 从缓存获取公钥
		return v.getPublicKey(ctx, issuer, kid, alg)
	})

	if err != nil {
		return &VerificationResult{
			Valid:  false,
			Method: "local",
			Error:  err,
		}, nil
	}

	if !token.Valid {
		return &VerificationResult{
			Valid:  false,
			Method: "local",
			Error:  fmt.Errorf("invalid token"),
		}, nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return &VerificationResult{
			Valid:  false,
			Method: "local",
			Error:  fmt.Errorf("invalid claims"),
		}, nil
	}

	// 验证基本声明
	if err := v.validateClaims(claims); err != nil {
		return &VerificationResult{
			Valid:  false,
			Method: "local",
			Error:  err,
			Claims: claims,
		}, nil
	}

	// 构建TokenInfo
	tokenInfo, err := v.buildTokenInfo(claims)
	if err != nil {
		return &VerificationResult{
			Valid:  false,
			Method: "local",
			Error:  err,
			Claims: claims,
		}, nil
	}

	return &VerificationResult{
		Valid:     true,
		TokenInfo: tokenInfo,
		Claims:    claims,
		Method:    "local",
		Issuer:    tokenInfo.Issuer,
	}, nil
}

// verifyRemote 远程内省验证
func (v *TokenVerifier) verifyRemote(ctx context.Context, tokenString string) (*VerificationResult, error) {
	v.metrics.mu.Lock()
	v.metrics.RemoteVerifications++
	v.metrics.mu.Unlock()

	// 检查缓存
	if cacheEntry := v.introspectionCache.Get(tokenString); cacheEntry != nil {
		v.metrics.mu.Lock()
		v.metrics.CacheHits++
		v.metrics.mu.Unlock()

		tokenInfo := v.introspectionToTokenInfo(cacheEntry.Response)
		return &VerificationResult{
			Valid:     cacheEntry.Response.Active,
			TokenInfo: tokenInfo,
			Method:    "remote",
			Issuer:    cacheEntry.Response.Issuer,
			CacheHit:  true,
		}, nil
	}

	v.metrics.mu.Lock()
	v.metrics.CacheMisses++
	v.metrics.mu.Unlock()

	// 尝试从每个发行者进行内省
	for _, issuerConfig := range v.config.Issuers {
		if issuerConfig.IntrospectionEndpoint == "" {
			continue
		}

		resp, err := v.introspectToken(ctx, tokenString, issuerConfig)
		if err != nil {
			continue // 尝试下一个发行者
		}

		// 缓存结果
		v.introspectionCache.Set(tokenString, resp, time.Duration(resp.ExpiresAt)*time.Second)

		tokenInfo := v.introspectionToTokenInfo(resp)
		return &VerificationResult{
			Valid:     resp.Active,
			TokenInfo: tokenInfo,
			Method:    "remote",
			Issuer:    resp.Issuer,
			CacheHit:  false,
		}, nil
	}

	return &VerificationResult{
		Valid:  false,
		Method: "remote",
		Error:  fmt.Errorf("no valid introspection endpoint found"),
	}, nil
}

// verifyHybrid 混合验证（同时进行本地和远程验证）
func (v *TokenVerifier) verifyHybrid(ctx context.Context, tokenString string) (*VerificationResult, error) {
	localCh := make(chan *VerificationResult, 1)
	remoteCh := make(chan *VerificationResult, 1)

	// 并行验证
	go func() {
		result, _ := v.verifyLocal(ctx, tokenString)
		localCh <- result
	}()

	go func() {
		result, _ := v.verifyRemote(ctx, tokenString)
		remoteCh <- result
	}()

	// 等待第一个成功的结果
	select {
	case localResult := <-localCh:
		if localResult.Valid {
			return localResult, nil
		}
		// 等待远程结果
		select {
		case remoteResult := <-remoteCh:
			return remoteResult, nil
		case <-time.After(v.config.RemoteVerification.Timeout):
			return localResult, nil
		}
	case remoteResult := <-remoteCh:
		if remoteResult.Valid {
			return remoteResult, nil
		}
		// 等待本地结果
		select {
		case localResult := <-localCh:
			return localResult, nil
		case <-time.After(100 * time.Millisecond):
			return remoteResult, nil
		}
	case <-ctx.Done():
		return &VerificationResult{
			Valid: false,
			Error: ctx.Err(),
		}, ctx.Err()
	}
}
