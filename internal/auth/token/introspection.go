package token

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// IntrospectionResponse RFC7662令牌内省响应
type IntrospectionResponse struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Username  string   `json:"username,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
	JTI       string   `json:"jti,omitempty"`
}

// introspectToken 内省令牌
func (v *TokenVerifier) introspectToken(ctx context.Context, token string, issuer IssuerConfig) (*IntrospectionResponse, error) {
	v.metrics.mu.Lock()
	v.metrics.IntrospectionCalls++
	v.metrics.mu.Unlock()

	data := url.Values{}
	data.Set("token", token)
	req, err := http.NewRequestWithContext(ctx, "POST", issuer.IntrospectionEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		v.metrics.mu.Lock()
		v.metrics.IntrospectionErrors++
		v.metrics.mu.Unlock()
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if issuer.ClientID != "" && issuer.ClientSecret != "" {
		req.SetBasicAuth(issuer.ClientID, issuer.ClientSecret)
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		v.metrics.mu.Lock()
		v.metrics.IntrospectionErrors++
		v.metrics.mu.Unlock()
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		v.metrics.mu.Lock()
		v.metrics.IntrospectionErrors++
		v.metrics.mu.Unlock()
		return nil, fmt.Errorf("introspection endpoint returned status %d", resp.StatusCode)
	}
	var ir IntrospectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&ir); err != nil {
		v.metrics.mu.Lock()
		v.metrics.IntrospectionErrors++
		v.metrics.mu.Unlock()
		return nil, err
	}
	return &ir, nil
}
