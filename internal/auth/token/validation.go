package token

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"strings"
	"time"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/errors"
)

// TokenInfo 包含验证后的令牌信息
type TokenInfo struct {
	Subject   string                 `json:"sub"`
	Audience  []string               `json:"aud"`
	Scopes    []string               `json:"scope"`
	ClientID  string                 `json:"client_id"`
	ExpiresAt time.Time              `json:"exp"`
	IssuedAt  time.Time              `json:"iat"`
	Active    bool                   `json:"active"`
	TokenType string                 `json:"token_type"`
	Claims    map[string]interface{} `json:"claims,omitempty"`
	TokenID   string                 `json:"jti,omitempty"`
	NotBefore time.Time              `json:"nbf,omitempty"`
	Issuer    string                 `json:"iss,omitempty"`
}

// validateClaims 验证JWT声明
func (v *TokenVerifier) validateClaims(claims jwt.MapClaims) error {
	now := time.Now()
	// exp
	if expv, ok := claims["exp"].(float64); ok {
		exp := time.Unix(int64(expv), 0)
		if now.After(exp.Add(v.config.ClockSkew)) {
			return errors.ErrExpiredToken
		}
	}
	// nbf
	if nbfv, ok := claims["nbf"].(float64); ok {
		nbf := time.Unix(int64(nbfv), 0)
		if now.Before(nbf.Add(-v.config.ClockSkew)) {
			return fmt.Errorf("token not valid yet")
		}
	}
	// iss
	if iss, ok := claims["iss"].(string); ok {
		if _, exists := v.issuerMap[iss]; !exists {
			return fmt.Errorf("unknown issuer: %s", iss)
		}
	} else {
		return fmt.Errorf("issuer (iss) claim missing")
	}
	return nil
}

// buildTokenInfo 构建TokenInfo
func (v *TokenVerifier) buildTokenInfo(claims jwt.MapClaims) (*TokenInfo, error) {
	ti := &TokenInfo{Active: true}
	if sub, ok := claims["sub"].(string); ok {
		ti.Subject = sub
	}
	if iss, ok := claims["iss"].(string); ok {
		ti.Issuer = iss
	}
	if expv, ok := claims["exp"].(float64); ok {
		ti.ExpiresAt = time.Unix(int64(expv), 0)
	}
	if iatv, ok := claims["iat"].(float64); ok {
		ti.IssuedAt = time.Unix(int64(iatv), 0)
	}
	if scopeS, ok := claims["scope"].(string); ok {
		ti.Scopes = strings.Split(scopeS, " ")
	}
	if cid, ok := claims["client_id"].(string); ok {
		ti.ClientID = cid
	}
	if audv, ok := claims["aud"].([]interface{}); ok {
		for _, a := range audv {
			if s, ok := a.(string); ok {
				ti.Audience = append(ti.Audience, s)
			}
		}
	}
	ti.TokenType = "Bearer"
	// keep raw claims
	ti.Claims = make(map[string]interface{})
	for k, v := range claims {
		ti.Claims[k] = v
	}
	return ti, nil
}

// introspectionToTokenInfo 将内省响应转换为TokenInfo
func (v *TokenVerifier) introspectionToTokenInfo(resp *IntrospectionResponse) *TokenInfo {
	ti := &TokenInfo{
		Active:    resp.Active,
		Subject:   resp.Subject,
		Audience:  resp.Audience,
		ClientID:  resp.ClientID,
		TokenType: resp.TokenType,
		Issuer:    resp.Issuer,
	}
	if resp.ExpiresAt > 0 {
		ti.ExpiresAt = time.Unix(resp.ExpiresAt, 0)
	}
	if resp.IssuedAt > 0 {
		ti.IssuedAt = time.Unix(resp.IssuedAt, 0)
	}
	if resp.NotBefore > 0 {
		ti.NotBefore = time.Unix(resp.NotBefore, 0)
	}
	if resp.Scope != "" {
		ti.Scopes = strings.Split(resp.Scope, " ")
	}
	return ti
}

// hasRequiredScopes 检查是否拥有必需的作用域
func (v *TokenVerifier) hasRequiredScopes(tokenScopes, requiredScopes []string) bool {
	if len(requiredScopes) == 0 {
		return true
	}
	m := make(map[string]bool)
	for _, s := range tokenScopes {
		m[s] = true
	}
	for _, r := range requiredScopes {
		if !m[r] {
			return false
		}
	}
	return true
}

// isSupportedAlgorithm 检查是否支持该算法
func (v *TokenVerifier) isSupportedAlgorithm(alg string) bool {
	for _, a := range v.config.LocalVerification.SupportedAlgorithms {
		if a == alg {
			return true
		}
	}
	return false
}
