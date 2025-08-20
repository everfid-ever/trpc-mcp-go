package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/httprc/v3"
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

// LocalJWKSConfig 本地 JWKS 配置
type LocalJWKSConfig struct {
	JWKS string // 本地 JWKS JSON 字符串
	File string // 本地 JWKS 文件路径
}

// RemoteJWKSConfig 远程 JWKS 配置
type RemoteJWKSConfig struct {
	URLs            []string          // 远程 JWKS URLs
	IssuerToURL     map[string]string // iss 到远程 URL 的映射
	RefreshInterval time.Duration     // 刷新间隔
}

// TokenVerifierConfig TokenVerifier 的配置
type TokenVerifierConfig struct {
	Local  *LocalJWKSConfig  // 本地 JWKS 配置
	Remote *RemoteJWKSConfig // 远程 JWKS 配置
}

// TokenVerifier 结构体
type TokenVerifier struct {
	localKeySet jwk.Set           // iss 到本地 jwk.Set 的映射
	cache       *jwk.Cache        // 远程模式缓存
	issuerToURL map[string]string // iss 到远程 URL 的映射
	isRemote    bool              // 是否使用远程模式
}

// NewLocalTokenVerifier 创建仅使用本地 JWKS 的 TokenVerifier
func NewLocalTokenVerifier(ctx context.Context, cfg LocalJWKSConfig) (*TokenVerifier, error) {
	verifier := &TokenVerifier{}

	defaultSet := jwk.NewSet()

	// 加载 JWKS 字符串
	if cfg.JWKS != "" {
		set, err := jwk.Parse([]byte(cfg.JWKS))
		if err != nil {
			return nil, fmt.Errorf("failed to parse local JWKS: %w", err)
		}
		for i := range set.Len() {
			key, _ := set.Key(i)
			_ = defaultSet.AddKey(key)
		}
	}

	// 加载 JWKS 文件
	if cfg.File != "" {
		set, err := jwk.ReadFile(cfg.File)
		if err != nil {
			return nil, fmt.Errorf("failed to parse local JWKS file: %w", err)
		}
		for i := range set.Len() {
			key, _ := set.Key(i)
			_ = defaultSet.AddKey(key)
		}
	}

	if len(defaultSet.Keys()) == 0 {
		return nil, fmt.Errorf("must provide JWKS or File")
	}

	verifier.localKeySet = defaultSet
	return verifier, nil
}

// NewRemoteTokenVerifier 创建仅使用远程 JWKS 的 TokenVerifier
func NewRemoteTokenVerifier(ctx context.Context, cfg RemoteJWKSConfig) (*TokenVerifier, error) {
	if len(cfg.URLs) == 0 {
		return nil, fmt.Errorf("must provide at least one RemoteURL")
	}

	refreshInterval := cfg.RefreshInterval
	if refreshInterval == 0 {
		// 默认 1 小时
		refreshInterval = 60 * time.Minute
	}

	cache, err := jwk.NewCache(ctx, httprc.NewClient())
	if err != nil {
		return nil, fmt.Errorf("failed to create jwk cache: %w", err)
	}
	for _, url_ := range cfg.URLs {
		if err := cache.Register(ctx, url_, jwk.WithConstantInterval(refreshInterval)); err != nil {
			return nil, fmt.Errorf("failed to register remote JWKS %s: %w", url_, err)
		}
	}

	return &TokenVerifier{
		cache:       cache,
		issuerToURL: cfg.IssuerToURL,
		isRemote:    true,
	}, nil
}

// NewTokenVerifier 创建综合 TokenVerifier
func NewTokenVerifier(ctx context.Context, cfg TokenVerifierConfig) (*TokenVerifier, error) {
	var verifier *TokenVerifier
	var err error

	if cfg.Remote != nil && len(cfg.Remote.URLs) > 0 {
		verifier, err = NewRemoteTokenVerifier(ctx, *cfg.Remote)
		if err != nil {
			return nil, err
		}
	}

	if cfg.Local != nil && (cfg.Local.JWKS != "" || cfg.Local.File != "") {
		localVerifier, err := NewLocalTokenVerifier(ctx, *cfg.Local)
		if err != nil {
			return nil, err
		}

		if verifier != nil {
			verifier.localKeySet = localVerifier.localKeySet
		} else {
			verifier = localVerifier
		}
	}

	if verifier == nil {
		return nil, errors.New("must provide either Local or Remote configuration")
	}

	return verifier, nil
}

// VerifyAccessToken 验证 JWT token，返回解析后的 token 或错误
func (v *TokenVerifier) VerifyAccessToken(ctx context.Context, tokenStr string) (AuthInfo, error) {
	// 先解析 token（不验证签名）以获取 iss
	unverifiedToken, err := jwt.ParseInsecure([]byte(tokenStr))
	if err != nil {
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrServerError, fmt.Sprintf("failed to parse token: %v", err.Error()), "")
	}

	// 获取 iss
	iss, ok := unverifiedToken.Issuer()
	if !ok || iss == "" {
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "failed to get iss from token", "")
	}

	// 获取 kid
	var kid string
	if err := unverifiedToken.Get("kid", &kid); err != nil {
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "failed to get kid from token", "")
	}

	// 尝试获取目标 keySet
	keySet, err := v.getTargetKeySet(ctx, iss, kid)
	if err != nil {
		return AuthInfo{}, err
	}

	// 验证 token,包括基本验证并配置时间验证偏差
	token, err := jwt.Parse([]byte(tokenStr),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(30*time.Second),
		// rfc 9068,对于exp、iat会自动验证合法性，其他此处只验证存在性
		jwt.WithRequiredClaim("exp"),
		jwt.WithRequiredClaim("aud"),
		jwt.WithRequiredClaim("sub"),
		jwt.WithRequiredClaim("client_id"),
		jwt.WithRequiredClaim("iat"),
		jwt.WithRequiredClaim("jti"),
		jwt.WithRequiredClaim("scope"),
	)
	if err != nil || token == nil {
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "failed to verify token", "")
	}

	// 校验sub字段非空
	if sub, ok := token.Subject(); !ok || sub == "" {
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "missing required 'sub' claim", "")
	}

	authInfo, err := v.convertJWTToAuthInfo(token, tokenStr)
	if err != nil {
		return AuthInfo{}, err
	}
	return authInfo, nil
}

func (v *TokenVerifier) getTargetKeySet(ctx context.Context, iss, kid string) (jwk.Set, error) {
	// 优先尝试本地 JWKS
	if _, ok := v.localKeySet.LookupKeyID(kid); ok {
		return v.localKeySet, nil
	}

	// 如果是远程模式，尝试远程 JWKS
	if v.isRemote {
		if url_, ok := v.issuerToURL[iss]; ok {
			keySet, err := v.cache.Lookup(ctx, url_)
			if err != nil {
				return nil, fmt.Errorf("failed to lookup remote JWKS for issuer %s: %w", iss, err)
			}
			return keySet, nil
		}
		return nil, fmt.Errorf("no remote JWKS URL found for issuer %s", iss)
	}

	return nil, fmt.Errorf("no JWKS found for issuer %s", iss)
}

// convertJWTToAuthInfo converts jwt.Token to AuthInfo structure.
func (v *TokenVerifier) convertJWTToAuthInfo(token jwt.Token, tokenStr string) (AuthInfo, error) {
	authInfo := AuthInfo{Token: tokenStr}

	// 提取 OAuth 字段
	var err error
	if authInfo.ClientID, err = extractClientID(token); err != nil {
		return AuthInfo{}, err
	}
	if authInfo.Resource, err = extractResource(token); err != nil {
		return AuthInfo{}, err
	}
	if authInfo.Scopes, err = extractScopes(token); err != nil {
		return AuthInfo{}, err
	}

	// optional fields
	authInfo.Extra = extractExtra(token)
	return authInfo, nil
}

// extractClientID extracts client ID with fallback chain
func extractClientID(token jwt.Token) (string, error) {
	clientID := ""
	if _ = token.Get("client_id", &clientID); clientID == "" {
		return "", errors.New("token does not contain valid client_id")
	}
	return clientID, nil
}

// extractScopes extracts scopes from various claim formats
func extractScopes(token jwt.Token) ([]string, error) {
	var scopes []string
	var tempScopes interface{}
	if err := token.Get("scope", &tempScopes); err != nil {
		switch s := tempScopes.(type) {
		case string:
			if s != "" {
				scopes = strings.Split(s, " ")
			} else {
				return scopes, errors.New("token does not contain valid scope")
			}
		case []string:
			if len(s) > 0 {
				scopes = s
			} else {
				return scopes, errors.New("token does not contain valid scope")
			}
		}
	}
	return scopes, nil
}

// extractResource extracts resource information
func extractResource(token jwt.Token) (*url.URL, error) {
	var aud []string
	if aud, ok := token.Audience(); !ok || len(aud) == 0 {
		return nil, fmt.Errorf("missing required 'aud' claim")
	}
	resourceStr := aud[0] //默认使用第一个 audience作为资源服务器标识符
	if resourceURL, err := url.Parse(resourceStr); err == nil && resourceURL != nil {
		resourceURL.Fragment = "" // 移除哈希片段（符合 RFC 8707）
		return resourceURL, nil
	}
	return nil, fmt.Errorf("invalid resource URL: %s", resourceStr)
}

// extractExtra extracts custom claims to Extra map
func extractExtra(token jwt.Token) map[string]interface{} {
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

// AddIssuerURL 动态添加或更新 issuer 到 JWKS URL 的映射,不提供动态删除功能
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

// ClearLocalKeys clears all locally cached keys.
func (v *TokenVerifier) ClearLocalKeys() {
	_ = v.localKeySet.Clear()
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

// GetCacheStats returns cache statistics for monitoring
// fixme 一般都是服务初始化时静态配置的，不需要监控吧?监控也没什么意义？
func (v *TokenVerifier) GetCacheStats() map[string]interface{} {

	return map[string]interface{}{
		"local_keys_count": v.localKeys.Len(),
		"jwks_url":         v.jwksURL,
		"remote_enabled":   v.remoteEnabled,
	}
}
