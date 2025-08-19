package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/lestrrat-go/httprc/v3"
	"net/url"
	"strings"
	"time"
	oauthErrors "trpc.group/trpc-go/trpc-mcp-go/internal/errors"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Standard JWT claims that should not be included in Extra
var standardClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true,
	"iat": true, "jti": true, "client_id": true, "scope": true,
	"scopes": true, "resource": true, "kid": true,
}

type TokenVerifierInterface interface {
	VerifyAccessToken(token string) (AuthInfo, error)
}

// TokenVerifierConfig 定义 TokenVerifier 的配置
type TokenVerifierConfig struct {
	// LocalJWKS: 本地 JWKS JSON 字符串（优先于 LocalFile）
	LocalJWKS string
	// LocalFile: 本地 JWKS 文件路径
	LocalFile string
	// RemoteURLs: 远程 JWKS URLs 列表（如果设置，则使用远程模式）
	RemoteURLs []string
	// IssuerToURL: iss 到远程 URL 的映射
	IssuerToURL map[string]string
	// IssuerToLocalJWKS: iss 到本地 JWKS 的映射（如果使用本地 JWKS）
	IssuerToLocalJWKS map[string]string
	// RefreshInterval: 远程 JWKS 刷新间隔（默认 5 分钟）
	RefreshInterval time.Duration
}

// TokenVerifier 结构体
// 必选 iss 字段
type TokenVerifier struct {
	localKeySets map[string]jwk.Set // iss 到本地 jwk.Set 的映射
	cache        *jwk.Cache         // 远程模式下使用的缓存
	issuerToURL  map[string]string  // iss 到远程 URL 的映射
	isRemote     bool               // 是否使用远程模式
}

// NewTokenVerifier 创建一个新的 TokenVerifier
func NewTokenVerifier(ctx context.Context, cfg TokenVerifierConfig) (*TokenVerifier, error) {
	verifier := &TokenVerifier{
		localKeySets: make(map[string]jwk.Set),
		issuerToURL:  cfg.IssuerToURL,
	}

	if len(cfg.RemoteURLs) > 0 {
		// 远程模式
		if cfg.RefreshInterval == 0 {
			cfg.RefreshInterval = 24 * time.Hour
		}
		cache, err := jwk.NewCache(ctx, httprc.NewClient())
		if err != nil {
			return nil, fmt.Errorf("failed to create jwk cache: %w", err)
		}
		for _, url_ := range cfg.RemoteURLs {
			if err := cache.Register(ctx, url_, jwk.WithConstantInterval(cfg.RefreshInterval)); err != nil {
				return nil, fmt.Errorf("failed to register remote JWKS %s: %w", url_, err)
			}
		}
		verifier.cache = cache
		verifier.isRemote = true
	}

	// 处理本地 JWKS（支持 iss 映射）
	if cfg.LocalJWKS != "" || cfg.LocalFile != "" || len(cfg.IssuerToLocalJWKS) > 0 {
		// 单 JWKS（无 iss 映射）
		if cfg.LocalJWKS != "" {
			set, err := jwk.Parse([]byte(cfg.LocalJWKS))
			if err != nil {
				return nil, fmt.Errorf("failed to parse local JWKS: %w", err)
			}
			verifier.localKeySets["default"] = set
		} else if cfg.LocalFile != "" {
			set, err := jwk.ReadFile(cfg.LocalFile)
			if err != nil {
				return nil, fmt.Errorf("failed to parse local JWKS file: %w", err)
			}
			verifier.localKeySets["default"] = set
		}

		// 按 iss 加载本地 JWKS
		for iss, jwks := range cfg.IssuerToLocalJWKS {
			set, err := jwk.Parse([]byte(jwks))
			if err != nil {
				return nil, fmt.Errorf("failed to parse local JWKS for issuer %s: %w", iss, err)
			}
			verifier.localKeySets[iss] = set
		}
	}

	if len(verifier.localKeySets) == 0 && len(cfg.RemoteURLs) == 0 {
		return nil, errors.New("must provide either RemoteURLs, LocalJWKS, LocalFile, or IssuerToLocalJWKS")
	}

	return verifier, nil
}

// validateOAuth21Claims validates OAuth 2.1 standard JWT claims according to RFC 6749, RFC 7519, and RFC 9068.
func (v *TokenVerifier) validateOAuth21Claims(jwtToken jwt.Token) error {

	// Verify subject
	//fixme 校验又重复
	if jwtToken.Subject() == "" {
		return fmt.Errorf("missing required 'sub' claim")
	}

	// Verify audience
	if len(jwtToken.Audience()) == 0 {
		return fmt.Errorf("missing required 'aud' claim")
	}

	// Verify token type specific claims
	return v.validateTokenTypeSpecificClaims(jwtToken, tokenType)
}

// VerifyAccessToken 验证 JWT token，返回解析后的 token 或错误
func (v *TokenVerifier) VerifyAccessToken(tokenStr string) (AuthInfo, error) {
	var iss string
	// 先解析 token（不验证签名）以获取 iss
	unverifiedToken, err := jwt.ParseInsecure([]byte(tokenStr))
	if err != nil {
		return nil, oauthErrors.NewOAuthError(oauthErrors.ErrServerError, fmt.Sprintf("failed to parse token: %w", err), "")
	}

	if iss, ok := unverifiedToken.Issuer(); !ok || iss == "" {
		return nil, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "failed to get iss from token", "")
	}

	keySet, err := v.getTargetKeySet(iss)
	if err != nil {
		return nil, err
	}

	// 验证 token,包括基本验证并配置时间验证偏差
	token, err := jwt.Parse([]byte(tokenStr),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(30*time.Second),
		// rfc 9068
		jwt.WithRequiredClaim("exp"),
		jwt.WithRequiredClaim("aud"),
		jwt.WithRequiredClaim("sub"),
		jwt.WithRequiredClaim("client_id"),
		jwt.WithRequiredClaim("iat"),
		jwt.WithRequiredClaim("jti"),
	)
	//todo 以下字段自行校验是否为空
	if jwtToken.Subject() == "" {
		return fmt.Errorf("missing required 'sub' claim")
	}
	// Verify audience
	if len(jwtToken.Audience()) == 0 {
		return fmt.Errorf("missing required 'aud' claim")
	}

	if err != nil {
		return nil, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "failed to verify token", "")
	}

	authInfo, err := v.convertJWTToAuthInfo(token, tokenStr)
	if err != nil {
		return AuthInfo{}, err
	}
	return authInfo, nil
}

func (v *TokenVerifier) getTargetKeySet(iss string) (jwk.Set, error) {
	var keySet jwk.Set
	if v.isRemote {
		// 优先尝试远程 JWKS
		url_, ok := v.issuerToURL[iss]
		if ok {
			keySet, err = v.cache.Lookup(ctx, url_)
			if err != nil {
				// 回退到本地 JWKS（如果存在）
				if localSet, ok := v.localKeySets[iss]; ok {
					keySet = localSet
				} else if defaultSet, ok := v.localKeySets["default"]; ok {
					keySet = defaultSet
				} else {
					return nil, fmt.Errorf("failed to lookup remote JWKS for issuer %s and no local fallback: %w", iss, err)
				}
			}
		} else if localSet, ok := v.localKeySets[iss]; ok {
			// 如果没有远程 URL，但有 iss 对应的本地 JWKS
			keySet = localSet
		} else if defaultSet, ok := v.localKeySets["default"]; ok {
			// 回退到默认本地 JWKS
			keySet = defaultSet
		} else {
			return nil, fmt.Errorf("no JWKS found for issuer %s", iss)
		}
	} else {
		// 仅本地模式
		if localSet, ok := v.localKeySets[iss]; ok {
			keySet = localSet
		} else if defaultSet, ok := v.localKeySets["default"]; ok {
			keySet = defaultSet
		} else {
			return nil, fmt.Errorf("no JWKS found for issuer %s", iss)
		}
	}
	return keySet, nil
}

// convertJWTToAuthInfo converts jwt.Token to AuthInfo structure.
func (v *TokenVerifier) convertJWTToAuthInfo(token jwt.Token, tokenStr string) (AuthInfo, error) {
	authInfo := AuthInfo{
		Token: tokenStr,
	}

	// Extract Basic OAuth fields with fallback chain
	authInfo.ClientID = v.extractClientID(token)
	authInfo.Scopes = v.extractScopes(token)
	authInfo.Resource = v.extractResource(token)
	authInfo.Extra = v.extractExtra(token)

	// Validate required fields
	// fixme 校验重复了
	if authInfo.ClientID == "" {
		return AuthInfo{}, errors.New("token does not contain valid client_id")
	}

	if authInfo.Subject == "" {
		return AuthInfo{}, errors.New("token does not contain valid subject")
	}

	return authInfo, nil
}

// extractClientID extracts client ID with fallback chain
func (v *TokenVerifier) extractClientID(token jwt.Token) string {
	clientID := ""
	_ = token.Get("client_id", &clientID)
	return clientID
}

// extractScopes extracts scopes from various claim formats
func (v *TokenVerifier) extractScopes(token jwt.Token) []string {
	var scopes []string
	var tempScopes interface{}
	if err := token.Get("scope", &tempScopes); err != nil {
		switch s := tempScopes.(type) {
		case string:
			if s != "" {
				scopes = strings.Split(s, " ")
			}
		case []string:
			scopes = s
		}
	}

	return scopes
}

// extractResource extracts resource information
func (v *TokenVerifier) extractResource(token jwt.Token) *url.URL {
	// Try "resource" field first
	var resourceStr string
	var resource interface{}
	if err := token.Get("resource", &resource); err == nil {
		if rs, ok := resource.(string); ok {
			resourceStr = rs
		}
	}

	// Try second audience entry as resource (RFC 8707)
	var audiences interface{}
	if err := token.Get("aud", &audiences); err != nil {
		if audArray, ok := audiences.([]string); ok && len(audArray) > 1 {
			resourceStr = audArray[1]
		}
	}

	if resourceURL, err := url.Parse(resourceStr); err != nil {
		resourceURL.Fragment = "" // 移除哈希片段（符合 RFC 8707）
		return resourceURL
	}
	return nil
}

// extractExtra extracts custom claims to Extra map
func (v *TokenVerifier) extractExtra(token jwt.Token) map[string]interface{} {
	extra := make(map[string]interface{})

	for _, key := range token.Keys() {
		if !standardClaims[key] {
			continue // 跳过已处理的声明与标准声明
		}
		var value interface{}
		if err := token.Get(key, &value); err == nil {
			extra[key] = value
		}
	}
	if len(extra) == 0 {
		return nil // 符合 omitempty
	}

	return extra
}

// AddIssuerURL 动态添加或更新 issuer 到 JWKS URL 的映射
func (v *TokenVerifier) AddIssuerURL(ctx context.Context, iss, url string, refreshInterval time.Duration) error {
	if !v.isRemote {
		return errors.New("cannot add issuer URL: remote JWKS support is disabled")
	}
	if url == "" {
		return errors.New("JWKS URL cannot be empty")
	}
	if !strings.HasPrefix(url, "https://") {
		return errors.New("JWKS URL must use HTTPS")
	}

	// 注册到 jwk.Cache
	if err := v.cache.Register(ctx, url, jwk.WithConstantInterval(refreshInterval)); err != nil {
		return fmt.Errorf("failed to register JWKS URL %s: %w", url, err)
	}
	v.issuerToURL[iss] = url
	return nil
}

// LoadLocalKey loads a JWK key for local verification.
// fixme 本地JWKS应在创建时加载，不应有该方法
func (v *JWKVerifier) LoadLocalKey(key jwk.Key) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.localKeys == nil {
		v.localKeys = jwk.NewSet()
	}
	return v.localKeys.AddKey(key)
}

// LoadLocalKeyFromBytes loads a key from raw bytes (PEM, etc.)
// fixme 不符合应用场景，JWKS都是json格式
func (v *JWKVerifier) LoadLocalKeyFromBytes(keyData []byte, keyID string) error {
	key, err := jwk.ParseKey(keyData)
	if err != nil {
		return fmt.Errorf("failed to parse key: %v", err)
	}

	// Set key ID if provided
	if keyID != "" {
		if err := key.Set(jwk.KeyIDKey, keyID); err != nil {
			return fmt.Errorf("failed to set key ID: %v", err)
		}
	}

	return v.LoadLocalKey(key)
}

// GetLocalKeys returns information about currently loaded local keys.
// fixme 源码底层就是根据use和kid来匹配JWKS，无需手动实现，应删除
func (v *JWKVerifier) GetLocalKeys() []map[string]interface{} {
	v.mu.Lock()
	defer v.mu.Unlock()

	var keys []map[string]interface{}

	if v.localKeys == nil {
		return keys
	}

	iter := v.localKeys.Keys(context.Background())
	for iter.Next(context.Background()) {
		pair := iter.Pair()
		key := pair.Value.(jwk.Key)

		keyInfo := map[string]interface{}{
			"kty": key.KeyType().String(),
			"use": "sig", // Default for signature verification
		}

		if keyID := key.KeyID(); keyID != "" {
			keyInfo["kid"] = keyID
		}

		keys = append(keys, keyInfo)
	}

	return keys
}

// ClearLocalKeys clears all locally cached keys.
func (v *TokenVerifier) ClearLocalKeys() {
	for _, set := range v.localKeySets {
		_ = set.Clear()
	}
}

// GetCacheStats returns cache statistics for monitoring
// fixme 一般都是服务初始化时静态配置的，不需要监控吧?
func (v *TokenVerifier) GetCacheStats() map[string]interface{} {

	return map[string]interface{}{
		"local_keys_count": v.localKeys.Len(),
		"jwks_url":         v.jwksURL,
		"remote_enabled":   v.remoteEnabled,
	}
}
