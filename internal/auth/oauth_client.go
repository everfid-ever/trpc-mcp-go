package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/pkce"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/token"
)

// OAuthClientProvider OAuth 2.1 客户端提供者
// 实现符合 MCP 2025-03-26 规范的客户端认证流程
type OAuthClientProvider struct {
	config      *ClientConfig
	httpClient  *http.Client
	tokenStore  token.TokenStore
	pkceManager *pkce.Manager

	// 状态管理
	mu            sync.RWMutex
	activeFlows   map[string]*AuthorizationFlow // state -> flow
	refreshTimers map[string]*time.Timer        // tokenID -> timer

	// 回调和钩子
	tokenRefreshCallback TokenRefreshCallback
	errorCallback        ErrorCallback

	// 统计信息
	stats *ClientStats
}

// ClientConfig 客户端配置
type ClientConfig struct {
	// OAuth 服务器信息
	AuthServerURL         string `json:"auth_server_url"`
	TokenEndpoint         string `json:"token_endpoint"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
	//客户端认证方式 "client_secret_basic" 或 "client_secret_post"
	ClientAuthMethod string `json:"client_auth_method,omitempty"`

	// 客户端凭证
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`

	// 重定向配置
	RedirectURI  string   `json:"redirect_uri"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`

	// 授权配置
	DefaultScopes []string `json:"default_scopes,omitempty"`

	// 令牌配置
	TokenRefreshThreshold time.Duration `json:"token_refresh_threshold"` // 提前刷新时间
	AutoRefreshEnabled    bool          `json:"auto_refresh_enabled"`

	// HTTP 配置
	HTTPTimeout time.Duration `json:"http_timeout"`
	MaxRetries  int           `json:"max_retries"`
	RetryDelay  time.Duration `json:"retry_delay"`

	// PKCE 配置
	PKCEEnabled    bool   `json:"pkce_enabled"` // OAuth 2.1 强制要求
	PKCEMethod     string `json:"pkce_method"`  // 固定为 S256
	VerifierLength int    `json:"verifier_length"`

	// 安全配置
	StateLength       int           `json:"state_length"`
	StateTimeout      time.Duration `json:"state_timeout"`
	AllowInsecureHTTP bool          `json:"allow_insecure_http"`

	// 高级配置
	UserAgent     string            `json:"user_agent"`
	CustomHeaders map[string]string `json:"custom_headers,omitempty"`
	EnableStats   bool              `json:"enable_stats"`
}

// AuthorizationFlow 授权流程状态
type AuthorizationFlow struct {
	// 基本信息
	State       string   `json:"state"`
	ClientID    string   `json:"client_id"`
	RedirectURI string   `json:"redirect_uri"`
	Scopes      []string `json:"scopes"`

	// PKCE 参数
	CodeVerifier  string `json:"code_verifier"`
	CodeChallenge string `json:"code_challenge"`

	// 时间信息
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`

	// 状态
	Completed   bool      `json:"completed"`
	CompletedAt time.Time `json:"completed_at,omitempty"`

	// 结果
	AuthorizationCode string `json:"authorization_code,omitempty"`
	Error             string `json:"error,omitempty"`
	ErrorDescription  string `json:"error_description,omitempty"`
}

// TokenRefreshCallback 令牌刷新回调
type TokenRefreshCallback func(oldToken, newToken *token.Token) error

// ErrorCallback 错误回调
type ErrorCallback func(err error, context string)

// ClientStats 客户端统计信息
type ClientStats struct {
	mu sync.RWMutex

	AuthorizationFlowsStarted   int64 `json:"authorization_flows_started"`
	AuthorizationFlowsCompleted int64 `json:"authorization_flows_completed"`
	AuthorizationFlowsFailed    int64 `json:"authorization_flows_failed"`

	TokensGenerated int64 `json:"tokens_generated"`
	TokensRefreshed int64 `json:"tokens_refreshed"`
	TokensRevoked   int64 `json:"tokens_revoked"`

	HTTPRequestsTotal   int64 `json:"http_requests_total"`
	HTTPRequestsSuccess int64 `json:"http_requests_success"`
	HTTPRequestsFailure int64 `json:"http_requests_failure"`

	LastActivity time.Time `json:"last_activity"`
}

// NewOAuthClientProvider 创建 OAuth 客户端提供者
func NewOAuthClientProvider(config *ClientConfig) (*OAuthClientProvider, error) {
	if err := validateClientConfig(config); err != nil {
		return nil, fmt.Errorf("invalid client config: %w", err)
	}

	// 设置默认值
	setClientConfigDefaults(config)

	// 创建 HTTP 客户端
	httpClient := &http.Client{
		Timeout: config.HTTPTimeout,
		// 可以添加自定义的 Transport 配置
	}

	// 创建 PKCE 管理器
	pkceConfig := &pkce.Config{
		ChallengeExpiry: config.StateTimeout,
		VerifierLength:  config.VerifierLength,
		EnableStats:     config.EnableStats,
	}
	pkceManager := pkce.NewManager(pkceConfig)

	provider := &OAuthClientProvider{
		config:        config,
		httpClient:    httpClient,
		tokenStore:    token.NewInMemoryTokenStore(),
		pkceManager:   pkceManager,
		activeFlows:   make(map[string]*AuthorizationFlow),
		refreshTimers: make(map[string]*time.Timer),
		stats:         &ClientStats{},
	}

	return provider, nil
}

// StartAuthorizationFlow 开始授权流程
func (c *OAuthClientProvider) StartAuthorizationFlow(scopes []string) (*AuthorizationFlow, error) {
	// 合并默认作用域
	allScopes := c.mergeScopes(scopes, c.config.DefaultScopes)

	// 生成安全的 state 参数
	state, err := c.generateSecureState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	// 生成 PKCE 参数
	var codeVerifier, codeChallenge string
	if c.config.PKCEEnabled {
		pkceChallenge, err := c.pkceManager.GenerateChallenge(c.config.ClientID)
		if err != nil {
			return nil, fmt.Errorf("failed to generate PKCE challenge: %w", err)
		}
		codeVerifier = pkceChallenge.Verifier
		codeChallenge = pkceChallenge.Challenge
	}

	// 创建授权流程
	flow := &AuthorizationFlow{
		State:         state,
		ClientID:      c.config.ClientID,
		RedirectURI:   c.config.RedirectURI,
		Scopes:        allScopes,
		CodeVerifier:  codeVerifier,
		CodeChallenge: codeChallenge,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(c.config.StateTimeout),
		Completed:     false,
	}

	// 存储流程状态
	c.mu.Lock()
	c.activeFlows[state] = flow
	c.mu.Unlock()

	// 更新统计
	if c.config.EnableStats {
		c.updateStats(func(stats *ClientStats) {
			stats.AuthorizationFlowsStarted++
			stats.LastActivity = time.Now()
		})
	}

	// 设置流程过期清理
	go func() {
		time.Sleep(c.config.StateTimeout)
		c.cleanupExpiredFlow(state)
	}()

	return flow, nil
}

// GetAuthorizationURL 获取授权 URL
func (c *OAuthClientProvider) GetAuthorizationURL(flow *AuthorizationFlow) (string, error) {
	if flow.Completed {
		return "", fmt.Errorf("authorization flow already completed")
	}

	if time.Now().After(flow.ExpiresAt) {
		return "", fmt.Errorf("authorization flow expired")
	}

	// 构建授权 URL
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", flow.ClientID)
	params.Set("redirect_uri", flow.RedirectURI)
	params.Set("state", flow.State)

	if len(flow.Scopes) > 0 {
		params.Set("scope", strings.Join(flow.Scopes, " "))
	}

	// OAuth 2.1 强制要求 PKCE
	if c.config.PKCEEnabled && flow.CodeChallenge != "" {
		params.Set("code_challenge", flow.CodeChallenge)
		params.Set("code_challenge_method", c.config.PKCEMethod)
	}

	authURL := c.config.AuthorizationEndpoint + "?" + params.Encode()
	return authURL, nil
}

func (c *OAuthClientProvider) isValidStateFormat(state string) bool {
	// 如果 state 为空直接 false
	if state == "" {
		return false
	}
	// 检查是否可被 base64.RawURLEncoding 解码
	if _, err := base64.RawURLEncoding.DecodeString(state); err != nil {
		return false
	}
	// 检查最大/最小长度
	if len(state) < 16 || len(state) > 256 {
		return false
	}
	return true
}

// CompleteAuthorizationFlow 完成授权流程
func (c *OAuthClientProvider) CompleteAuthorizationFlow(code, state string) (*token.Token, error) {
	if code == "" || state == "" {
		return nil, fmt.Errorf("missing authorization code or state")
	}

	if !c.isValidStateFormat(state) {
		c.updateFailureStats()
		return nil, fmt.Errorf("invalid state format")
	}

	// 查找并验证流程
	c.mu.RLock()
	flow, exists := c.activeFlows[state]
	c.mu.RUnlock()

	if !exists {
		c.updateFailureStats()
		return nil, fmt.Errorf("invalid or expired state")
	}

	if flow.Completed {
		return nil, fmt.Errorf("authorization flow already completed")
	}

	if time.Now().After(flow.ExpiresAt) {
		c.cleanupExpiredFlow(state)
		c.updateFailureStats()
		return nil, fmt.Errorf("authorization flow expired")
	}

	// 交换授权码获取令牌
	token, err := c.exchangeCodeForToken(code, flow)
	if err != nil {
		c.updateFailureStats()
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// 标记流程完成
	c.mu.Lock()
	flow.Completed = true
	flow.CompletedAt = time.Now()
	flow.AuthorizationCode = code
	c.mu.Unlock()

	// 存储令牌
	if err := c.tokenStore.StoreToken(context.Background(), token); err != nil {
		return nil, fmt.Errorf("failed to store token: %w", err)
	}

	// 设置自动刷新
	if c.config.AutoRefreshEnabled && token.RefreshToken != "" {
		c.scheduleTokenRefresh(token)
	}

	// 清理流程
	go func() {
		time.Sleep(time.Minute) // 延迟清理，防止重复请求
		c.cleanupFlow(state)
	}()

	// 更新统计
	if c.config.EnableStats {
		c.updateStats(func(stats *ClientStats) {
			stats.AuthorizationFlowsCompleted++
			stats.TokensGenerated++
			stats.LastActivity = time.Now()
		})
	}

	return token, nil
}

// ClientCredentialsFlow 客户端凭证流程
func (c *OAuthClientProvider) ClientCredentialsFlow(scopes []string) (*token.Token, error) {
	if c.config.ClientSecret == "" {
		return nil, fmt.Errorf("client secret required for client credentials flow")
	}

	// 合并作用域
	allScopes := c.mergeScopes(scopes, c.config.DefaultScopes)

	// 构建请求
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.config.ClientID)
	data.Set("client_secret", c.config.ClientSecret)

	if len(allScopes) > 0 {
		data.Set("scope", strings.Join(allScopes, " "))
	}

	// 发送令牌请求
	tokenResp, err := c.sendTokenRequest(data)
	if err != nil {
		return nil, fmt.Errorf("client credentials flow failed: %w", err)
	}

	// 创建令牌对象
	token := &token.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresIn:   tokenResp.ExpiresIn,
		ExpiresAt:   time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		Scope:       tokenResp.Scope,
		TokenID:     tokenResp.TokenID,
		IssuedAt:    time.Now(),
		ClientID:    c.config.ClientID,
		// 客户端凭证流程通常不返回刷新令牌
	}

	// 存储令牌
	if err := c.tokenStore.StoreToken(context.Background(), token); err != nil {
		return nil, fmt.Errorf("failed to store token: %w", err)
	}

	// 更新统计
	if c.config.EnableStats {
		c.updateStats(func(stats *ClientStats) {
			stats.TokensGenerated++
			stats.LastActivity = time.Now()
		})
	}

	return token, nil
}

// RefreshToken 刷新令牌
func (c *OAuthClientProvider) RefreshToken(refreshToken string) (*token.Token, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh token is required")
	}

	// 构建刷新请求
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", c.config.ClientID)

	if c.config.ClientSecret != "" {
		data.Set("client_secret", c.config.ClientSecret)
	}

	// 发送令牌请求
	tokenResp, err := c.sendTokenRequest(data)
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	// 创建新令牌
	newToken := &token.Token{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		RefreshToken: tokenResp.RefreshToken,
		Scope:        tokenResp.Scope,
		TokenID:      tokenResp.TokenID,
		IssuedAt:     time.Now(),
		ClientID:     c.config.ClientID,
	}

	// 如果没有返回新的刷新令牌，使用原来的
	if newToken.RefreshToken == "" {
		newToken.RefreshToken = refreshToken
	}

	// 存储新令牌
	if err := c.tokenStore.StoreToken(context.Background(), newToken); err != nil {
		return nil, fmt.Errorf("failed to store refreshed token: %w", err)
	}

	// 设置新的自动刷新
	if c.config.AutoRefreshEnabled && newToken.RefreshToken != "" {
		c.scheduleTokenRefresh(newToken)
	}

	// 更新统计
	if c.config.EnableStats {
		c.updateStats(func(stats *ClientStats) {
			stats.TokensRefreshed++
			stats.LastActivity = time.Now()
		})
	}

	return newToken, nil
}

// RevokeToken 撤销令牌
func (c *OAuthClientProvider) RevokeToken(token string) error {
	if c.config.RevocationEndpoint == "" {
		return fmt.Errorf("revocation endpoint not configured")
	}

	if token == "" {
		return fmt.Errorf("token is required")
	}

	// 构建撤销请求
	data := url.Values{}
	data.Set("token", token)

	var body io.Reader = strings.NewReader(data.Encode())
	req, err := http.NewRequest("POST", c.config.RevocationEndpoint, body)
	if err != nil {
		return fmt.Errorf("revoke token request failed: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.setCommonHeaders(req)

	if c.config.ClientAuthMethod == "client_secret_basic" && c.config.ClientSecret != "" {
		basicAuth := base64.StdEncoding.EncodeToString([]byte(c.config.ClientID + ":" + c.config.ClientSecret))
		req.Header.Set("Authorization", "Basic "+basicAuth)
	} else if c.config.ClientSecret != "" {
		data.Set("client_id", c.config.ClientID)
		data.Set("client_secret", c.config.ClientSecret)
		body = strings.NewReader(data.Encode())
		req.Body = io.NopCloser(body)
	}

	resp, err := c.doHTTPRequest(req)
	if err != nil {
		return fmt.Errorf("revocation request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revocation failed: %s", resp.Status)
	}

	// 更新统计
	if c.config.EnableStats {
		c.updateStats(func(stats *ClientStats) {
			stats.TokensRevoked++
			stats.LastActivity = time.Now()
		})
	}

	return nil
}

// GetValidToken 获取有效的访问令牌（自动刷新）
func (c *OAuthClientProvider) GetValidToken() (*token.Token, error) {
	token, err := c.tokenStore.GetTokenByClientID(context.Background(), c.config.ClientID)
	if err != nil {
		return nil, fmt.Errorf("no token found: %w", err)
	}

	// 检查令牌是否即将过期
	if c.isTokenExpiringSoon(token) && token.RefreshToken != "" {
		// 尝试刷新令牌
		refreshedToken, err := c.RefreshToken(token.RefreshToken)
		if err != nil {
			// 刷新失败，返回原令牌（如果还有效）
			if time.Now().Before(token.ExpiresAt) {
				return token, nil
			}
			return nil, fmt.Errorf("token expired and refresh failed: %w", err)
		}
		return refreshedToken, nil
	}

	// 检查令牌是否已过期
	if time.Now().After(token.ExpiresAt) {
		return nil, fmt.Errorf("token expired")
	}

	return token, nil
}

// 内部辅助方法

func (c *OAuthClientProvider) exchangeCodeForToken(code string, flow *AuthorizationFlow) (*token.Token, error) {
	// 构建令牌交换请求
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", flow.ClientID)
	data.Set("redirect_uri", flow.RedirectURI)

	if c.config.ClientSecret != "" {
		data.Set("client_secret", c.config.ClientSecret)
	}

	// OAuth 2.1 PKCE 验证
	if c.config.PKCEEnabled && flow.CodeVerifier != "" {
		data.Set("code_verifier", flow.CodeVerifier)
	}

	// 发送令牌请求
	tokenResp, err := c.sendTokenRequest(data)
	if err != nil {
		return nil, err
	}

	// 创建令牌对象
	token := &token.Token{
		AccessToken:  tokenResp.AccessToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    tokenResp.ExpiresIn,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		RefreshToken: tokenResp.RefreshToken,
		Scope:        tokenResp.Scope,
		TokenID:      tokenResp.TokenID,
		IssuedAt:     time.Now(),
		ClientID:     flow.ClientID,
	}

	return token, nil
}

func (c *OAuthClientProvider) sendTokenRequest(data url.Values) (*TokenResponse, error) {

	var body io.Reader = strings.NewReader(data.Encode())
	req, err := http.NewRequest("POST", c.config.TokenEndpoint, body)

	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	c.setCommonHeaders(req)

	// 客户端认证方式
	if c.config.ClientAuthMethod == "client_secret_basic" && c.config.ClientSecret != "" {
		baseAuth := base64.StdEncoding.EncodeToString([]byte(c.config.ClientID + ":" + c.config.ClientSecret))
		req.Header.Set("Authorization", "Basic "+baseAuth)
	} else if c.config.ClientSecret != "" {
		data.Set("client_id", c.config.ClientID)
		data.Set("client_secret", c.config.ClientSecret)
		body = strings.NewReader(data.Encode())
		req.Body = io.NopCloser(body)
	}

	resp, err := c.doHTTPRequest(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("token request failed: nil response")
	}
	defer func() {
		if resp.Body != nil {
			resp.Body.Close()
		}
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errorResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(respBody, &errorResp) == nil && errorResp.Error != "" {
			return nil, fmt.Errorf("token request failed: %s - %s", errorResp.Error, errorResp.ErrorDescription)
		}
		return nil, fmt.Errorf("token request failed: %s", resp.Status)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}

func (c *OAuthClientProvider) doHTTPRequest(req *http.Request) (*http.Response, error) {
	if c.config.EnableStats {
		c.updateStats(func(stats *ClientStats) {
			stats.HTTPRequestsTotal++
		})
	}

	var resp *http.Response
	var err error

	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(c.config.RetryDelay * time.Duration(attempt))
		}

		resp, err = c.httpClient.Do(req)
		// 如果没有网络错误且有响应，且状态码 < 500 表示不需要重试
		if err == nil && resp != nil && resp.StatusCode < 500 {
			break
		}

		// 若需要重试且 resp 非 nil，关闭 body 避免泄露
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}

	// 更新统计
	if c.config.EnableStats {
		c.updateStats(func(stats *ClientStats) {
			if err == nil && resp != nil && resp.StatusCode < 400 {
				stats.HTTPRequestsSuccess++
			} else {
				stats.HTTPRequestsFailure++
			}
		})
	}

	return resp, err
}

func (c *OAuthClientProvider) setCommonHeaders(req *http.Request) {
	if c.config.UserAgent != "" {
		req.Header.Set("User-Agent", c.config.UserAgent)
	}

	for key, value := range c.config.CustomHeaders {
		req.Header.Set(key, value)
	}
}

func (c *OAuthClientProvider) generateSecureState() (string, error) {
	// 最小熵 16 字节
	length := c.config.StateLength
	if length < 16 {
		length = 16
	}
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func (c *OAuthClientProvider) mergeScopes(requested, defaults []string) []string {
	scopeMap := make(map[string]bool)

	// 添加默认作用域
	for _, scope := range defaults {
		scopeMap[scope] = true
	}

	// 添加请求的作用域
	for _, scope := range requested {
		scopeMap[scope] = true
	}

	// 转换回切片
	var result []string
	for scope := range scopeMap {
		result = append(result, scope)
	}

	return result
}

func (c *OAuthClientProvider) scheduleTokenRefresh(token *token.Token) {
	// 计算刷新时间
	refreshTime := token.ExpiresAt.Add(-c.config.TokenRefreshThreshold)
	if refreshTime.Before(time.Now()) {
		refreshTime = time.Now().Add(time.Minute) // 至少1分钟后
	}

	// 取消之前的定时器
	c.mu.Lock()
	if timer, exists := c.refreshTimers[token.TokenID]; exists {
		timer.Stop()
	}
	c.mu.Unlock()

	// 设置新的刷新定时器
	timer := time.AfterFunc(time.Until(refreshTime), func() {
		if _, err := c.RefreshToken(token.RefreshToken); err != nil {
			if c.errorCallback != nil {
				c.errorCallback(err, "automatic token refresh")
			}
		}
	})

	c.mu.Lock()
	c.refreshTimers[token.TokenID] = timer
	c.mu.Unlock()
}

func (c *OAuthClientProvider) isTokenExpiringSoon(token *token.Token) bool {
	return time.Until(token.ExpiresAt) <= c.config.TokenRefreshThreshold
}

func (c *OAuthClientProvider) cleanupExpiredFlow(state string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if flow, exists := c.activeFlows[state]; exists {
		if time.Now().After(flow.ExpiresAt) {
			delete(c.activeFlows, state)
		}
	}
}

func (c *OAuthClientProvider) cleanupFlow(state string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.activeFlows, state)
}

func (c *OAuthClientProvider) updateStats(updateFunc func(*ClientStats)) {
	c.stats.mu.Lock()
	updateFunc(c.stats)
	c.stats.mu.Unlock()
}

func (c *OAuthClientProvider) updateFailureStats() {
	if c.config.EnableStats {
		c.updateStats(func(stats *ClientStats) {
			stats.AuthorizationFlowsFailed++
			stats.LastActivity = time.Now()
		})
	}
}

// GetStats 获取统计信息
func (c *OAuthClientProvider) GetStats() *ClientStats {
	if !c.config.EnableStats {
		return nil
	}

	c.stats.mu.RLock()
	defer c.stats.mu.RUnlock()

	// 返回副本
	stats := *c.stats
	return &stats
}

// SetTokenRefreshCallback 设置令牌刷新回调
func (c *OAuthClientProvider) SetTokenRefreshCallback(callback TokenRefreshCallback) {
	c.tokenRefreshCallback = callback
}

// SetErrorCallback 设置错误回调
func (c *OAuthClientProvider) SetErrorCallback(callback ErrorCallback) {
	c.errorCallback = callback
}

// Close 关闭客户端提供者
func (c *OAuthClientProvider) Close() {
	// 停止所有刷新定时器
	c.mu.Lock()
	for _, timer := range c.refreshTimers {
		if timer != nil {
			timer.Stop()
		}
	}
	c.refreshTimers = make(map[string]*time.Timer)

	// 清理活跃流程
	c.activeFlows = make(map[string]*AuthorizationFlow)
	c.mu.Unlock()

	// 关闭 PKCE 管理器
	if c.pkceManager != nil {
		c.pkceManager.Close()
	}

	// 关闭 tokenStore 如果支持 Close()
	if closer, ok := c.tokenStore.(interface{ Close() error }); ok {
		closer.Close() // 忽略错误
	}

	// 关闭 http idle 连接（如果 transport 支持）
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

// validateClientConfig 配置验证和默认值设置
func validateClientConfig(config *ClientConfig) error {
	if config.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}

	if config.AuthorizationEndpoint == "" {
		return fmt.Errorf("authorization_endpoint is required")
	}

	if config.TokenEndpoint == "" {
		return fmt.Errorf("token_endpoint is required")
	}

	if config.RedirectURI == "" {
		return fmt.Errorf("redirect_uri is required")
	}

	// 安全检查
	if !config.AllowInsecureHTTP {
		if !strings.HasPrefix(config.AuthorizationEndpoint, "https://") {
			return fmt.Errorf("authorization_endpoint must use HTTPS")
		}
		if !strings.HasPrefix(config.TokenEndpoint, "https://") {
			return fmt.Errorf("token_endpoint must use HTTPS")
		}
	}

	return nil
}

func setClientConfigDefaults(config *ClientConfig) {
	if config.HTTPTimeout == 0 {
		config.HTTPTimeout = 30 * time.Second
	}

	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}

	if config.RetryDelay == 0 {
		config.RetryDelay = time.Second
	}

	if config.TokenRefreshThreshold == 0 {
		config.TokenRefreshThreshold = 5 * time.Minute
	}

	if config.StateLength == 0 {
		config.StateLength = 32
	}

	if config.StateTimeout == 0 {
		config.StateTimeout = 10 * time.Minute
	}

	if config.VerifierLength == 0 {
		config.VerifierLength = 128
	}

	// OAuth 2.1 强制要求 PKCE
	config.PKCEEnabled = true
	config.PKCEMethod = "S256"

	if config.ClientAuthMethod == "" {
		config.ClientAuthMethod = "client_secret_post"
	}

	if config.UserAgent == "" {
		config.UserAgent = "OAuth2.1-Client/1.0"
	}
}
