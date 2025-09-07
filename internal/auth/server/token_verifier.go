// Tencent is pleased to support the open source community by making trpc-mcp-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-mcp-go is licensed under the Apache License Version 2.0.

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	oauthErrors "trpc.group/trpc-go/trpc-mcp-go/internal/errors"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Standard JWT claims that should not be included in Extra
var standardClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "iat": true,
	"jti": true, "client_id": true, "scope": true, "kid": true,
}

type TokenVerifierInterface interface {
	VerifyAccessToken(ctx context.Context, token string) (AuthInfo, error)
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
	Local         *LocalJWKSConfig     // 本地 JWKS 配置
	Remote        *RemoteJWKSConfig    // 远程 JWKS 配置
	Introspection *IntrospectionConfig // 远程 introspection 配置（RFC7662）
}

// IntrospectionCredentials introspection 客户端凭据
type IntrospectionCredentials struct {
	ClientID     string
	ClientSecret string
}

// IntrospectionConfig 远程 introspection 配置
type IntrospectionConfig struct {
	// 默认 introspection 端点（可选）。当找不到与 issuer 绑定的端点时使用。
	Endpoint string
	// 根据 issuer 选择不同端点（多租户）。
	IssuerToEndpoint map[string]string

	// 默认凭据以及每个 issuer 的凭据（可选）。
	DefaultCredentials *IntrospectionCredentials
	IssuerCredentials  map[string]IntrospectionCredentials

	// HTTP 超时
	Timeout time.Duration

	// 缓存 TTL（正向）与负缓存 TTL（inactive 或 4xx/401 等）。
	CacheTTL         time.Duration
	NegativeCacheTTL time.Duration

	// 当 JWT 验签失败时是否回退到 introspection。
	UseOnJWTFail bool
}

// TokenVerifier 结构体
type TokenVerifier struct {
	localKeySet jwk.Set           // iss 到本地 jwk.Set 的映射
	cache       *jwk.Cache        // 远程 JWKS 缓存（jwx v2）
	issuerToURL map[string]string // iss 到远程 URL 的映射
	isRemote    bool              // 是否使用远程模式

	// RFC7662 introspection
	introspectionEnabled   bool
	httpClient             *http.Client
	defaultIntrospectEP    string
	issuerToIntrospectEP   map[string]string
	defaultCreds           *IntrospectionCredentials
	issuerCreds            map[string]IntrospectionCredentials
	useIntrospectionOnFail bool

	// 简单内存缓存
	introspectCache   map[string]introspectionCacheEntry
	introspectCacheMu sync.RWMutex
	cacheTTL          time.Duration
	negativeCacheTTL  time.Duration
}

type TokenVerifierFunc func(ctx context.Context, token string) (AuthInfo, error)

func (f TokenVerifierFunc) VerifyAccessToken(ctx context.Context, token string) (AuthInfo, error) {
	return f(ctx, token)
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
		for i := 0; i < set.Len(); i++ {
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
		for i := 0; i < set.Len(); i++ {
			key, _ := set.Key(i)
			_ = defaultSet.AddKey(key)
		}
	}

	if defaultSet.Len() == 0 {
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

	// jwx v2 缓存
	cache := jwk.NewCache(ctx)
	for _, url_ := range cfg.URLs {
		_ = cache.Register(url_)
	}

	return &TokenVerifier{
		cache: cache,
		issuerToURL: func() map[string]string {
			if cfg.IssuerToURL == nil {
				return nil
			}
			m := make(map[string]string, len(cfg.IssuerToURL))
			for k, v := range cfg.IssuerToURL {
				m[k] = v
			}
			return m
		}(),
		isRemote: true,
	}, nil
}

// NewTokenVerifier 创建综合 TokenVerifier
// 只需提供一种或多种配置即可工作。SDK 将自动按“本地 → 远程 → introspection（如启用）
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
		// 若未提供 JWKS，则允许构建“仅 introspection”模式
		if cfg.Introspection != nil {
			verifier = &TokenVerifier{}
		} else {
			return nil, errors.New("no verification method configured: configure Local JWKS (Local), or Remote JWKS (Remote), or Introspection")
		}
	}

	// 初始化 introspection（可选）
	if cfg.Introspection != nil {
		to := cfg.Introspection.Timeout
		if to <= 0 {
			to = 5 * time.Second
		}
		verifier.httpClient = &http.Client{Timeout: to}
		verifier.defaultIntrospectEP = cfg.Introspection.Endpoint
		// 复制 IssuerToEndpoint，防止外部后续修改
		if cfg.Introspection.IssuerToEndpoint != nil {
			verifier.issuerToIntrospectEP = make(map[string]string, len(cfg.Introspection.IssuerToEndpoint))
			for k, v := range cfg.Introspection.IssuerToEndpoint {
				verifier.issuerToIntrospectEP[k] = v
			}
		}
		// 复制 DefaultCredentials
		if cfg.Introspection.DefaultCredentials != nil {
			dc := *cfg.Introspection.DefaultCredentials
			verifier.defaultCreds = &dc
		}
		// 复制 IssuerCredentials
		if cfg.Introspection.IssuerCredentials != nil {
			verifier.issuerCreds = make(map[string]IntrospectionCredentials, len(cfg.Introspection.IssuerCredentials))
			for k, v := range cfg.Introspection.IssuerCredentials {
				verifier.issuerCreds[k] = v
			}
		}
		verifier.useIntrospectionOnFail = cfg.Introspection.UseOnJWTFail
		verifier.cacheTTL = cfg.Introspection.CacheTTL
		if verifier.cacheTTL <= 0 {
			verifier.cacheTTL = 60 * time.Second
		}
		verifier.negativeCacheTTL = cfg.Introspection.NegativeCacheTTL
		if verifier.negativeCacheTTL <= 0 {
			verifier.negativeCacheTTL = 15 * time.Second
		}
		verifier.introspectionEnabled = true
		verifier.introspectCache = make(map[string]introspectionCacheEntry)
	}

	// 不设置显式“模式”，在 Verify 阶段按配置动态选择

	return verifier, nil
}

// VerifyAccessToken 验证 JWT token，返回解析后的 token 或错误
func (v *TokenVerifier) VerifyAccessToken(ctx context.Context, tokenStr string) (AuthInfo, error) {
	// 未配置任何 JWKS 且启用 introspection：直接走 introspection（兼容 opaque/JWT）
	if v.localKeySet == nil && !v.isRemote && v.introspectionEnabled {
		ai, err := v.introspectAccessToken(ctx, tokenStr, "")
		if err != nil {
			return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "failed to verify token", "")
		}
		return ai, nil
	}

	// 先解析 token（不验证签名）以获取 iss；若失败且启用 introspection，则直接尝试 introspection（支持 opaque token）。
	unverifiedToken, err := jwt.ParseInsecure([]byte(tokenStr))
	if err != nil {
		if v.introspectionEnabled {
			if ai, ierr := v.introspectAccessToken(ctx, tokenStr, ""); ierr == nil {
				return ai, nil
			}
		}
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "malformed token: cannot parse header/payload; if you are using opaque tokens, enable Introspection", "")
	}

	// 获取 iss
	iss := unverifiedToken.Issuer()
	if iss == "" {
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "missing issuer (iss) in token", "")
	}

	// 从 JWS Header 中获取 kid
	kid, err := extractKIDFromHeader(tokenStr)
	if err != nil || kid == "" {
		// 尝试 introspection 回退
		if v.introspectionEnabled && v.useIntrospectionOnFail {
			if ai, ierr := v.introspectAccessToken(ctx, tokenStr, iss); ierr == nil {
				return ai, nil
			}
		}
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "missing key id (kid) in JWS header; if your tokens omit kid, ensure the JWKS only contains one key or use Introspection fallback", "")
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
		jwt.WithRequiredClaim("iat"),
	)
	if err != nil || token == nil {
		// JWT 验签失败，策略化回退到 introspection（若启用）
		if v.introspectionEnabled && v.useIntrospectionOnFail {
			if ai, ierr := v.introspectAccessToken(ctx, tokenStr, iss); ierr == nil {
				return ai, nil
			}
		}
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "signature validation failed or claims invalid; ensure JWKS is configured for issuer or enable Introspection fallback", "")
	}

	// 校验sub字段非空
	if sub := token.Subject(); sub == "" {
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
	if v.localKeySet != nil {
		if _, ok := v.localKeySet.LookupKeyID(kid); ok {
			return v.localKeySet, nil
		}
	}

	// 如果是远程模式，尝试远程 JWKS
	if v.isRemote {
		if url_, ok := v.issuerToURL[iss]; ok {
			if v.cache != nil {
				if keySet, err := v.cache.Get(ctx, url_); err == nil {
					if _, ok := keySet.LookupKeyID(kid); !ok {
						if refreshed, ferr := jwk.Fetch(ctx, url_); ferr == nil {
							if _, ok2 := refreshed.LookupKeyID(kid); ok2 {
								return refreshed, nil
							}
						}
					}
					return keySet, nil
				}
			}
			keySet, err := jwk.Fetch(ctx, url_)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch remote JWKS for issuer %s (url=%s): %w", iss, url_, err)
			}
			return keySet, nil
		}
		return nil, fmt.Errorf("no remote JWKS URL found for issuer %s: provide Remote.IssuerToURL mapping", iss)
	}

	return nil, fmt.Errorf("no JWKS found for issuer %s: neither Local nor Remote key set available", iss)
}

// ---- RFC7662 introspection 实现 ----

type introspectionCacheEntry struct {
	authInfo  AuthInfo
	inactive  bool
	expiresAt time.Time
}

func (v *TokenVerifier) resolveIntrospectionEndpoint(issuer string) (string, *IntrospectionCredentials) {
	ep := ""
	if issuer != "" && v.issuerToIntrospectEP != nil {
		if e, ok := v.issuerToIntrospectEP[issuer]; ok {
			ep = e
		}
	}
	if ep == "" {
		ep = v.defaultIntrospectEP
	}
	var creds *IntrospectionCredentials
	if issuer != "" && v.issuerCreds != nil {
		if c, ok := v.issuerCreds[issuer]; ok {
			cc := c
			creds = &cc
		}
	}
	if creds == nil {
		creds = v.defaultCreds
	}
	return ep, creds
}

func (v *TokenVerifier) introspectionCacheKey(endpoint, token string) string {
	return endpoint + "|" + token
}

func (v *TokenVerifier) loadFromIntrospectionCache(key string) (introspectionCacheEntry, bool) {
	v.introspectCacheMu.RLock()
	defer v.introspectCacheMu.RUnlock()
	entry, ok := v.introspectCache[key]
	if !ok {
		return introspectionCacheEntry{}, false
	}
	if time.Now().After(entry.expiresAt) {
		return introspectionCacheEntry{}, false
	}
	return entry, true
}

func (v *TokenVerifier) storeToIntrospectionCache(key string, entry introspectionCacheEntry) {
	v.introspectCacheMu.Lock()
	v.introspectCache[key] = entry
	v.introspectCacheMu.Unlock()
}

func (v *TokenVerifier) introspectAccessToken(ctx context.Context, tokenStr, issuer string) (AuthInfo, error) {
	if !v.introspectionEnabled {
		return AuthInfo{}, errors.New("introspection not enabled")
	}
	endpoint, creds := v.resolveIntrospectionEndpoint(issuer)
	if endpoint == "" {
		return AuthInfo{}, errors.New("no introspection endpoint configured: set Introspection.Endpoint or IssuerToEndpoint for the issuer")
	}

	key := v.introspectionCacheKey(endpoint, tokenStr)
	if entry, ok := v.loadFromIntrospectionCache(key); ok {
		if entry.inactive {
			return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "inactive token", "")
		}
		return entry.authInfo, nil
	}

	form := url.Values{}
	form.Set("token", tokenStr)
	form.Set("token_type_hint", "access_token")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return AuthInfo{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if creds != nil && creds.ClientID != "" {
		basic := creds.ClientID + ":" + creds.ClientSecret
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(basic)))
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return AuthInfo{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		v.storeToIntrospectionCache(key, introspectionCacheEntry{inactive: true, expiresAt: time.Now().Add(v.negativeCacheTTL)})
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "introspection request failed", "")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return AuthInfo{}, err
	}
	active, _ := payload["active"].(bool)
	if !active {
		v.storeToIntrospectionCache(key, introspectionCacheEntry{inactive: true, expiresAt: time.Now().Add(v.negativeCacheTTL)})
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "inactive token", "")
	}

	ai, err := v.convertIntrospectionToAuthInfo(payload, tokenStr)
	if err != nil {
		return AuthInfo{}, err
	}

	ttl := v.cacheTTL
	if expV, ok := payload["exp"]; ok {
		switch t := expV.(type) {
		case float64:
			expTs := time.Unix(int64(t), 0)
			if expTs.After(time.Now()) {
				rem := time.Until(expTs)
				if rem < ttl {
					ttl = rem
				}
			}
		case json.Number:
			if v, err2 := t.Int64(); err2 == nil {
				expTs := time.Unix(v, 0)
				if expTs.After(time.Now()) {
					rem := time.Until(expTs)
					if rem < ttl {
						ttl = rem
					}
				}
			}
		}
	}
	v.storeToIntrospectionCache(key, introspectionCacheEntry{authInfo: ai, expiresAt: time.Now().Add(ttl)})
	return ai, nil
}

func (v *TokenVerifier) convertIntrospectionToAuthInfo(payload map[string]interface{}, tokenStr string) (AuthInfo, error) {
	var ai AuthInfo
	ai.Token = tokenStr
	if cid, _ := payload["client_id"].(string); cid != "" {
		ai.ClientID = cid
	}
	if sc, ok := payload["scope"]; ok {
		ai.Scopes = parseScopesFromRaw(sc)
	}
	switch exp := payload["exp"].(type) {
	case float64:
		ts := int64(exp)
		ai.ExpiresAt = &ts
	case json.Number:
		if v, err := exp.Int64(); err == nil {
			ai.ExpiresAt = &v
		}
	}
	if r, err := extractResourceFromIntrospection(payload["aud"]); err == nil {
		ai.Resource = r
	}

	extra := make(map[string]interface{})
	for k, v := range payload {
		if standardClaims[k] {
			continue
		}
		switch k {
		case "active", "username", "token_type", "token_type_hint":
			continue
		case "client_id", "scope", "exp", "aud", "iss", "sub", "iat", "jti":
			continue
		default:
			extra[k] = v
		}
	}
	if len(extra) > 0 {
		ai.Extra = extra
	}
	return ai, nil
}

func parseScopesFromRaw(raw interface{}) []string {
	switch s := raw.(type) {
	case string:
		if s == "" {
			return nil
		}
		return strings.Split(s, " ")
	case []interface{}:
		var scopes []string
		for _, v := range s {
			if str, ok := v.(string); ok && str != "" {
				scopes = append(scopes, str)
			}
		}
		if len(scopes) == 0 {
			return nil
		}
		return scopes
	default:
		return nil
	}
}

func extractResourceFromIntrospection(audRaw interface{}) (*url.URL, error) {
	if audRaw == nil {
		return nil, nil
	}
	var candidates []string
	switch v := audRaw.(type) {
	case string:
		if v != "" {
			candidates = []string{v}
		}
	case []interface{}:
		for _, it := range v {
			if s, ok := it.(string); ok && s != "" {
				candidates = append(candidates, s)
			}
		}
	case []string:
		candidates = v
	}
	for _, c := range candidates {
		looksLikeURL := strings.HasPrefix(c, "http://") || strings.HasPrefix(c, "https://") || strings.Contains(c, "://")
		if !looksLikeURL {
			continue
		}
		u, err := url.Parse(c)
		if err != nil || u == nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		u.Fragment = ""
		return u, nil
	}
	return nil, nil
}

// extractKIDFromHeader 从 JWS Header 提取 kid
func extractKIDFromHeader(tokenStr string) (string, error) {
	msg, err := jws.Parse([]byte(tokenStr))
	if err != nil {
		return "", fmt.Errorf("failed to parse JWS: %w", err)
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return "", errors.New("no signatures found in JWS")
	}

	// 优先从受保护头读取
	if ph := sigs[0].ProtectedHeaders(); ph != nil {
		if v, ok := ph.Get(jws.KeyIDKey); ok {
			if kid, ok2 := v.(string); ok2 && kid != "" {
				return kid, nil
			}
		}
	}
	return "", errors.New("missing kid in JWS header")
}

// convertJWTToAuthInfo converts jwt.Token to AuthInfo structure.
func (v *TokenVerifier) convertJWTToAuthInfo(token jwt.Token, tokenStr string) (AuthInfo, error) {
	authInfo := AuthInfo{Token: tokenStr}

	// 写入 exp -> ExpiresAt （一定要在最前面做）
	if exp := token.Expiration(); !exp.IsZero() {
		ts := exp.Unix()
		authInfo.ExpiresAt = &ts
	} else {
		// 正常不会走到这里，因为上面 Parse 时用了 WithRequiredClaim("exp")
		// 但为了健壮性，返回 invalid_token 更清晰
		return AuthInfo{}, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "missing exp claim", "")
	}

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

	// 其他自定义声明
	authInfo.Extra = extractExtra(token)
	return authInfo, nil
}

// extractClientID extracts client ID (optional)
func extractClientID(token jwt.Token) (string, error) {
	// client_id is not mandatory for access tokens (RFC9068)
	if v, ok := token.Get("client_id"); ok {
		if s, ok2 := v.(string); ok2 && s != "" {
			return s, nil
		}
	}
	// Fallback to azp (often used in OIDC)
	if v, ok := token.Get("azp"); ok {
		if s, ok2 := v.(string); ok2 && s != "" {
			return s, nil
		}
	}
	// Missing client identifier is acceptable
	return "", nil
}

// extractScopes extracts scopes from various claim formats (scope/scp). Missing is acceptable.
func extractScopes(token jwt.Token) ([]string, error) {
	var raw interface{}
	// Prefer RFC6749 style "scope" (space-delimited string or array)
	if v, ok := token.Get("scope"); ok {
		raw = v
	} else {
		// Fallback to "scp" (array of strings used by some providers)
		if v2, ok2 := token.Get("scp"); ok2 {
			raw = v2
		} else {
			// No scopes present → treat as empty without error
			return nil, nil
		}
	}

	switch s := raw.(type) {
	case string:
		if s == "" {
			return nil, nil
		}
		return strings.Split(s, " "), nil
	case []string:
		if len(s) == 0 {
			return nil, nil
		}
		return s, nil
	case []interface{}:
		if len(s) == 0 {
			return nil, nil
		}
		var scopes []string
		for _, v := range s {
			if str, ok := v.(string); ok {
				scopes = append(scopes, str)
			}
		}
		if len(scopes) == 0 {
			return nil, nil
		}
		return scopes, nil
	default:
		// Unknown format → ignore rather than failing hard for compatibility
		return nil, nil
	}
}

// extractResource extracts resource information
func extractResource(token jwt.Token) (*url.URL, error) {
	aud := token.Audience()
	if len(aud) == 0 {
		return nil, fmt.Errorf("missing required 'aud' claim")
	}

	// 遍历查找第一个看起来像 URL 并且可解析为 HTTP(S) 的值；
	// 若都不是 URL，则返回 nil，表示未提供资源指示器。
	for _, candidate := range aud {
		if candidate == "" {
			continue
		}
		looksLikeURL := strings.HasPrefix(candidate, "http://") || strings.HasPrefix(candidate, "https://") || strings.Contains(candidate, "://")
		if !looksLikeURL {
			continue
		}
		resourceURL, err := url.Parse(candidate)
		if err != nil || resourceURL == nil {
			continue
		}
		if resourceURL.Scheme == "" || resourceURL.Host == "" {
			continue
		}
		resourceURL.Fragment = "" // 移除哈希片段（符合 RFC 8707）
		return resourceURL, nil
	}
	return nil, nil
}

// extractExtra extracts custom claims to Extra map
func extractExtra(token jwt.Token) map[string]interface{} {
	all, _ := token.AsMap(context.Background())
	if len(all) == 0 {
		return nil
	}

	extra := make(map[string]interface{})
	for key, value := range all {
		if standardClaims[key] {
			continue
		}
		switch key {
		case "active", "username", "token_type", "token_type_hint":
			continue
		case "client_id", "scope", "exp", "aud", "iss", "sub", "iat", "jti":
			continue
		default:
			extra[key] = value
		}
	}
	if len(extra) == 0 {
		return nil
	}
	return extra
}

// 注意：TokenVerifier 为静态配置。初始化后不支持动态添加 issuer 映射或清空本地 KeySet。
