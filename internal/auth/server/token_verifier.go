package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type TokenVerifierInterface interface {
	VerifyAccessToken(token string) (AuthInfo, error)
}

// TokenType defines the type of token (access or refresh).
type TokenType string

const (
	AccessToken  TokenType = "access"
	RefreshToken TokenType = "refresh"
)

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
// 注意验证的 token 必须包含 iss 字段
type TokenVerifier struct {
	localKeySets map[string]jwk.Set // iss 到本地 jwk.Set 的映射
	cache        *jwk.Cache         // 远程模式下使用的缓存
	issuerToURL  map[string]string
	isRemote     bool
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

// Verify 验证 JWT token，返回解析后的 token 或错误
func (v *TokenVerifier) Verify(ctx context.Context, tokenString string) (jwt.Token, error) {
	var iss string
	// 先解析 token（不验证签名）以获取 iss
	unverifiedToken, err := jwt.Parse([]byte(tokenString), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("failed to parse token for issuer: %w", err)
	}

	if iss, ok := unverifiedToken.Issuer(); !ok || iss == "" {
		return nil, errors.New("token missing issuer claim")
	}

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

	// 验证 token（包括签名和标准声明）
	token, err := jwt.Parse([]byte(tokenString), jwt.WithKeySet(keySet), jwt.WithValidate(true))

	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}
	return token, nil
}

// convertJWTToAuthInfo converts jwt.Token to AuthInfo structure.
func (v *TokenVerifier) convertJWTToAuthInfo(jwtToken jwt.Token, token string) (AuthInfo, error) {
	authInfo := AuthInfo{
		Token: token,
	}

	// Extract client_id with fallback chain
	authInfo.ClientID = v.extractClientID(jwtToken)

	// Extract scopes
	authInfo.Scopes = v.extractScopes(jwtToken)

	// Extract expiration time
	if exp, _ := jwtToken.Expiration(); !exp.IsZero() {
		expiresAt := exp.Unix()
		authInfo.ExpiresAt = &expiresAt
	}

	// Extract resource information
	authInfo.Resource = v.extractResource(jwtToken)

	// Extract custom fields to Extra
	authInfo.Extra = v.extractExtraClaims(jwtToken)

	// Validate required fields
	if authInfo.ClientID == "" {
		return AuthInfo{}, errors.New("token does not contain valid client_id")
	}

	return authInfo, nil
}

// extractClientID extracts client ID with fallback chain
func (v *TokenVerifier) extractClientID(jwtToken jwt.Token) string {
	// Try client_id first
	if clientID, ok := jwtToken.Get("client_id"); ok {
		if clientIDStr, ok := clientID.(string); ok {
			return clientIDStr
		}
	}

	// Try aud (audience) as fallback
	if aud := jwtToken.Audience(); len(aud) > 0 {
		return aud[0]
	}

	// Try sub (subject) as last resort
	if sub := jwtToken.Subject(); sub != "" {
		return sub
	}

	return ""
}

// extractScopes extracts scopes from various claim formats
func (v *TokenVerifier) extractScopes(jwtToken jwt.Token) []string {
	// Try "scope" field first (OAuth 2.1 standard)
	if scopesClaim, ok := jwtToken.Get("scope"); ok {
		switch scopes := scopesClaim.(type) {
		case string:
			return v.splitScopes(scopes)
		case []interface{}:
			return v.convertInterfaceArrayToStrings(scopes)
		case []string:
			return scopes
		}
	}

	// Try "scopes" field as alternative
	if scopesClaim, ok := jwtToken.Get("scopes"); ok {
		if scopesArray, ok := scopesClaim.([]interface{}); ok {
			return v.convertInterfaceArrayToStrings(scopesArray)
		}
	}

	return []string{}
}

// extractResource extracts resource information
func (v *TokenVerifier) extractResource(jwtToken jwt.Token) *url.URL {
	// Try "resource" field first
	if resourceClaim, ok := jwtToken.Get("resource"); ok {
		if resourceStr, ok := resourceClaim.(string); ok {
			if resourceURL, err := url.Parse(resourceStr); err == nil {
				return resourceURL
			}
		}
	}

	// Try second audience entry as resource (RFC 8707)
	if audienceClaim, ok := jwtToken.Get("aud"); ok {
		if audArray, ok := audienceClaim.([]interface{}); ok && len(audArray) > 1 {
			if resourceStr, ok := audArray[1].(string); ok {
				if resourceURL, err := url.Parse(resourceStr); err == nil {
					return resourceURL
				}
			}
		}
	}

	return nil
}

// extractExtraClaims extracts custom claims to Extra map
func (v *TokenVerifier) extractExtraClaims(jwtToken jwt.Token) map[string]interface{} {
	extra := make(map[string]interface{})

	// Standard JWT claims that should not be included in Extra
	standardClaims := map[string]bool{
		"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true,
		"iat": true, "jti": true, "client_id": true, "scope": true,
		"scopes": true, "resource": true, "kid": true,
	}

	// Extract all claims
	claimsMap, err := jwtToken.AsMap(context.Background())
	if err != nil {
		return extra
	}

	// Filter out standard claims
	for key, value := range claimsMap {
		if !standardClaims[key] {
			extra[key] = value
		}
	}

	return extra
}

// convertInterfaceArrayToStrings converts []interface{} to []string
func (v *TokenVerifier) convertInterfaceArrayToStrings(arr []interface{}) []string {
	strs := make([]string, 0, len(arr))
	for _, item := range arr {
		if str, ok := item.(string); ok {
			strs = append(strs, str)
		}
	}
	return strs
}

// splitScopes splits scope string by spaces, handling multiple consecutive spaces.
func (v *TokenVerifier) splitScopes(scopeStr string) []string {
	if scopeStr == "" {
		return []string{}
	}
	// Use strings.Fields to handle multiple spaces and trim
	return strings.Fields(scopeStr)
}

// GetCacheStats returns cache statistics for monitoring
func (v *TokenVerifier) GetCacheStats() map[string]interface{} {

	return map[string]interface{}{
		"local_keys_count": v.localKeys.Len(),
		"jwks_url":         v.jwksURL,
		"remote_enabled":   v.remoteEnabled,
	}
}
