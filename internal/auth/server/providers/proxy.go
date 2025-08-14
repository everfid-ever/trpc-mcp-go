package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-playground/validator/v10"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/errors"
)

// ProxyEndpoints defines the OAuth 2.0/2.1 server endpoints used by the proxy.
// It contains the URLs for various OAuth operations.
//
// ProxyEndpoints 定义了代理使用的 OAuth 2.0/2.1 服务器端点。
// 它包含了各种 OAuth 操作的 URL。
type ProxyEndpoints struct {
	// AuthorizationURL is the URL of the OAuth 2.0/2.1 authorization endpoint.
	// This is where users are redirected to authorize the client.
	//
	// AuthorizationURL 是 OAuth 2.0/2.1 授权端点的 URL。
	// 这是用户被重定向以授权客户端的地址。
	// "https://auth.example.com/authorize"
	AuthorizationURL string `json:"authorizationUrl"`

	// TokenURL is the URL of the OAuth 2.0/2.1 token endpoint.
	// This is where the client exchanges an authorization code for an access token.
	//
	// TokenURL 是 OAuth 2.0/2.1 令牌端点的 URL。
	// 这是客户端用授权码交换访问令牌的地址。
	// "https://auth.example.com/token"
	TokenURL string `json:"tokenUrl"`

	// RevocationURL is the optional URL of the OAuth 2.0 token revocation endpoint.
	// If provided, it's used to revoke access tokens or refresh tokens.
	//
	// RevocationURL 是可选的 OAuth 2.0 令牌撤销端点的 URL。
	// 如果提供，用于撤销访问令牌或刷新令牌。
	// "https://auth.example.com/revoke"
	RevocationURL string `json:"revocationUrl,omitempty"`

	// RegistrationURL is the optional URL of the OAuth 2.0 dynamic client registration endpoint.
	// If provided, it allows clients to register with the authorization server dynamically.
	//
	// RegistrationURL 是可选的 OAuth 2.0 动态客户端注册端点的 URL。
	// 如果提供，允许客户端动态注册到授权服务器。
	// "https://auth.example.com/register"
	RegistrationURL string `json:"registrationUrl,omitempty"`
}

// ProxyOptions 定义代理OAuth服务器的配置选项
// Defines configuration options for the proxy OAuth server
type ProxyOptions struct {
	// Endpoints 代理OAuth操作的端点配置
	// Individual endpoint URLs for proxying specific OAuth operations
	Endpoints ProxyEndpoints

	// VerifyAccessToken 验证访问令牌并返回认证信息的函数
	// Function to verify access tokens and return auth info
	VerifyAccessToken func(token string) (*server.AuthInfo, error)

	// GetClient 从上游服务器获取客户端信息的函数
	// Function to fetch client information from the upstream server
	GetClient func(clientID string) (*auth.OAuthClientInformationFull, error)

	// Fetch 自定义HTTP请求函数，用于所有网络请求，可选
	// Custom fetch implementation used for all network requests, optional
	Fetch auth.FetchFunc
}

// ProxyOAuthServerProvider 代理OAuth服务器提供者
// Proxy OAuth server provider
type ProxyOAuthServerProvider struct {
	// endpoints 代理端点配置
	// Proxy endpoint configuration
	endpoints ProxyEndpoints

	// verifyAccessToken 验证访问令牌的函数
	// Function to verify access tokens
	verifyAccessToken func(token string) (*server.AuthInfo, error)

	// getClient 获取客户端信息的函数
	// Function to fetch client information
	getClient func(clientID string) (*auth.OAuthClientInformationFull, error)

	// SkipLocalPkceValidation 是否跳过本地PKCE验证。
	// 如果为true，服务器不会在本地执行PKCE验证，而是将code_verifier传递给上游服务器。
	// 注意：仅当上游服务器执行实际的PKCE验证时，此值应为true。
	// Whether to skip local PKCE validation.
	// If true, the server will not perform PKCE validation locally and will pass the code_verifier to the upstream server.
	// NOTE: This should only be true if the upstream server is performing the actual PKCE validation.
	// 可选字段，默认false / Optional field, defaults to false
	SkipLocalPkceValidation bool `json:"skipLocalPkceValidation,omitempty"`

	// Custom fetch implementation, optional
	fetch auth.FetchFunc
}

// Authorize 处理OAuth授权请求并重定向到授权端点
// Handles OAuth authorization requests and redirects to the authorization endpoint
func (p *ProxyOAuthServerProvider) Authorize(client auth.OAuthClientInformationFull, params server.AuthorizationParams, res http.ResponseWriter, req *http.Request) error {
	// 验证授权端点URL
	// Validate the authorization endpoint URL
	targetURL, err := url.Parse(p.endpoints.AuthorizationURL)
	if err != nil {
		return fmt.Errorf("invalid authorization URL: %v", err)
	}

	// 构建必需的OAuth查询参数
	// Build required OAuth query parameters
	query := url.Values{
		"client_id":             {client.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {params.RedirectURI},
		"code_challenge":        {params.CodeChallenge},
		"code_challenge_method": {"S256"},
	}

	// 添加可选的OAuth参数
	// Add optional OAuth parameters
	if params.State != "" {
		query.Set("state", params.State)
	}
	if len(params.Scopes) > 0 {
		query.Set("scope", strings.Join(params.Scopes, " "))
	}
	if params.Resource != nil {
		query.Set("resource", params.Resource.String())
	}

	// 设置查询参数并生成重定向URL
	// Set query parameters and generate the redirect URL
	targetURL.RawQuery = query.Encode()

	// 执行HTTP重定向
	// Perform HTTP redirect
	http.Redirect(res, req, targetURL.String(), http.StatusFound)
	return nil
}

func (p *ProxyOAuthServerProvider) VerifyAccessToken(token string) (*server.AuthInfo, error) {
	return p.verifyAccessToken(token)
}

// NewProxyOAuthServerProvider 构造函数，初始化代理OAuth服务器提供者
// Constructor to initialize the proxy OAuth server provider
func NewProxyOAuthServerProvider(options ProxyOptions) *ProxyOAuthServerProvider {
	provider := &ProxyOAuthServerProvider{
		endpoints:               options.Endpoints,
		verifyAccessToken:       options.VerifyAccessToken,
		getClient:               options.GetClient,
		fetch:                   options.Fetch,
		SkipLocalPkceValidation: true,
	}
	return provider
}

// doFetch 辅助方法：执行HTTP请求
// Helper method: performs an HTTP request
func (p *ProxyOAuthServerProvider) doFetch(req *http.Request) (*http.Response, error) {
	if p.fetch != nil {
		return p.fetch(req.URL.String(), req)
	}
	client := &http.Client{}
	return client.Do(req)
}

func (p *ProxyOAuthServerProvider) RevokeToken(client auth.OAuthClientInformationFull, request auth.OAuthTokenRevocationRequest) error {
	if p.endpoints.RevocationURL == "" {
		return fmt.Errorf("no revocation endpoint configured")
	}
	params := url.Values{
		"token":     {request.Token},
		"client_id": {client.ClientID},
	}
	if client.ClientSecret != "" {
		params.Set("client_secret", client.ClientSecret)
	}
	if request.TokenTypeHint != "" {
		params.Set("token_type_hint", request.TokenTypeHint)
	}
	req, err := http.NewRequest("POST", p.endpoints.RevocationURL, strings.NewReader(params.Encode()))
	if err != nil {
		return fmt.Errorf("create request failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.doFetch(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.NewOAuthError(errors.ErrServerError, fmt.Sprintf("Token revocation failed: %v", resp.StatusCode), "")
	}

	return nil
}

// ClientsStore 返回 OAuthRegisteredClientsStore
// Returns an OAuthRegisteredClientsStore
func (p *ProxyOAuthServerProvider) ClientsStore() *server.OAuthClientsStore {
	var store *server.OAuthClientsStore

	if p.endpoints.RegistrationURL != "" {
		// 设置动态客户端注册功能
		registerClient := func(client auth.OAuthClientInformationFull) (*auth.OAuthClientInformationFull, error) {
			// 序列化客户端信息为 JSON
			// Serialize client information to JSON
			body, err := json.Marshal(client)
			if err != nil {
				//todo 日志化错误
				return nil, fmt.Errorf("failed to marshal client: %v", err)
			}

			// 创建 HTTP 请求
			// Create HTTP request
			req, err := http.NewRequest("POST", p.endpoints.RegistrationURL, bytes.NewReader(body))
			if err != nil {
				//todo 日志化错误
				return nil, fmt.Errorf("failed to create request: %v", err)
			}
			req.Header.Set("Content-Type", "application/json")

			// 执行 HTTP 请求
			// Perform HTTP request
			resp, err := p.doFetch(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			// 检查响应状态
			// Check response status
			if resp.StatusCode != http.StatusOK {
				// return nil, &ServerError{Message: fmt.Sprintf("client registration failed: %v", resp.StatusCode)
				return nil, errors.NewOAuthError(errors.ErrServerError, fmt.Sprintf("client registration failed: %v", resp.StatusCode), "")
			}

			// 解析响应
			// Parse response
			var data auth.OAuthClientInformationFull
			if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
				//todo 日志化错误
				return nil, fmt.Errorf("failed to decode response: %v", err)
			}

			// 返回客户端信息（假设无需额外验证，Zod 验证可在此添加）
			// Return client information (assuming no additional validation; Zod validation can be added here)
			return &data, nil
		}
		store = server.NewOAuthClientStoreSupportDynamicRegistration(p.getClient, registerClient)
	} else {
		// 不支持动态客户端注册
		store = server.NewOAuthClientStore(p.getClient)
	}

	return store
}

// ChallengeForAuthorizationCode 返回指定授权开始时使用的 codeChallenge 值。
// Returns the `codeChallenge` that was used when the indicated authorization began.
func (p *ProxyOAuthServerProvider) ChallengeForAuthorizationCode(client auth.OAuthClientInformationFull, authorizationCode string) (string, error) {
	// In a proxy setup, we don't store the code challenge ourselves
	// Instead, we proxy the token request and let the upstream server validate it
	return "", nil
}

func (p *ProxyOAuthServerProvider) ExchangeAuthorizationCode(client auth.OAuthClientInformationFull, authorizationCode string, codeVerifier *string, redirectUri *string, resource *url.URL) (*auth.OAuthTokens, error) {
	// 验证 token URL
	// Validate token URL
	if p.endpoints.TokenURL == "" {
		return nil, fmt.Errorf("no token endpoint configured")
	}
	// 构建表单参数
	// Build form parameters
	params := url.Values{
		"grant_type": {"authorization_code"},
		"client_id":  {client.ClientID},
		"code":       {authorizationCode},
	}
	if client.ClientSecret != "" {
		params.Set("client_secret", client.ClientSecret)
	}
	if codeVerifier != nil {
		params.Set("code_verifier", *codeVerifier)
	}
	if redirectUri != nil {
		params.Set("redirect_uri", *redirectUri)
	}
	if resource != nil {
		params.Set("resource", resource.String())
	}

	// 创建 HTTP 请求
	// Create HTTP request
	req, err := http.NewRequest("POST", p.endpoints.TokenURL, bytes.NewReader([]byte(params.Encode())))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// 执行 HTTP 请求
	// Perform HTTP request
	resp, err := p.doFetch(req)
	if err != nil {
		return nil, errors.NewOAuthError(errors.ErrServerError, fmt.Sprintf("token exchange failed: %v", resp.StatusCode), "")
	}
	defer resp.Body.Close()

	// 检查响应状态
	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, errors.NewOAuthError(errors.ErrServerError, fmt.Sprintf("token exchange failed: %v", resp.StatusCode), "")
	}

	// 解析响应 JSON
	// Parse response JSON
	var data auth.OAuthTokens
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	// 返回令牌
	// Return tokens
	return &data, nil
}

func (p *ProxyOAuthServerProvider) ExchangeRefreshToken(
	client auth.OAuthClientInformationFull,
	refreshToken string,
	scopes []string, // 可选，若为空表示未提供 / Optional, empty slice if not provided
	resource *url.URL, // 可选，若为nil表示未提供 / Optional, nil if not provided
) (*auth.OAuthTokens, error) {
	params := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {client.ClientID},
		"refresh_token": {refreshToken},
	}
	if client.ClientSecret != "" {
		params.Set("client_secret", client.ClientSecret)
	}
	if len(scopes) > 0 {
		params.Set("scope", strings.Join(scopes, " "))
	}
	if resource != nil {
		params.Set("resource", resource.String())
	}

	// 创建HTTP请求
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, p.endpoints.TokenURL, bytes.NewBufferString(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// 使用自定义fetch或默认HTTP客户端
	fetch := p.fetch
	if fetch == nil {
		fetch = func(url string, req *http.Request) (*http.Response, error) {
			return http.DefaultClient.Do(req)
		}
	}

	// 发送请求
	resp, err := fetch(p.endpoints.TokenURL, req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		return nil, errors.NewOAuthError(errors.ErrServerError, fmt.Sprintf("token refresh failed: %v", resp.StatusCode), "")
	}

	// 解析响应
	var data auth.OAuthTokens
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	// 验证响应数据（使用 validator/v10）
	if err := validateOAuthTokens(&data); err != nil {
		return nil, fmt.Errorf("validation failed: %v", err)
	}

	return &data, nil
}

// validateOAuthTokens 验证OAuthTokens结构体
func validateOAuthTokens(tokens *auth.OAuthTokens) error {
	validate := validator.New()
	if err := validate.Struct(tokens); err != nil {
		return fmt.Errorf("validation errors: %v", err)
	}
	return nil
}
