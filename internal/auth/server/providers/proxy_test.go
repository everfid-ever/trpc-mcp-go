// Tencent is pleased to support the open source community by making trpc-mcp-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-mcp-go is licensed under the Apache License Version 2.0.

package providers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
)

// 测试NewProxyOAuthServerProvider
func TestNewProxyOAuthServerProvider(t *testing.T) {
	options := ProxyOptions{
		Endpoints: ProxyEndpoints{
			AuthorizationURL: "https://example.com/auth",
			TokenURL:         "https://example.com/token",
		},
		VerifyAccessToken: func(token string) (*server.AuthInfo, error) {
			return &server.AuthInfo{}, nil
		},
		GetClient: func(clientID string) (*auth.OAuthClientInformationFull, error) {
			return &auth.OAuthClientInformationFull{}, nil
		},
	}

	provider := NewProxyOAuthServerProvider(options)
	assert.NotNil(t, provider)
	assert.True(t, provider.SkipLocalPkceValidation)
}

// 测试Authorize方法
func TestProxyOAuthServerProvider_Authorize(t *testing.T) {
	provider := &ProxyOAuthServerProvider{
		endpoints: ProxyEndpoints{
			AuthorizationURL: "https://example.com/auth",
		},
	}

	client := new(auth.OAuthClientInformationFull)
	client.ClientID = "test-client"

	params := server.AuthorizationParams{
		RedirectURI:   "https://redirect.com/callback",
		CodeChallenge: "challenge123",
		State:         "state123",
		Scopes:        []string{"read", "write"},
		Resource:      nil,
	}

	// 创建一个ResponseRecorder来记录响应
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "https://example.com/authorize", nil)

	err := provider.Authorize(*client, params, recorder, req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusFound, recorder.Code)
	assert.Contains(t, recorder.Header().Get("Location"), "https://example.com/auth")
	assert.Contains(t, recorder.Header().Get("Location"), "client_id=test-client")
	assert.Contains(t, recorder.Header().Get("Location"), "response_type=code")
	assert.Contains(t, recorder.Header().Get("Location"), "redirect_uri=https%3A%2F%2Fredirect.com%2Fcallback")
	assert.Contains(t, recorder.Header().Get("Location"), "code_challenge=challenge123")
	assert.Contains(t, recorder.Header().Get("Location"), "state=state123")
	assert.Contains(t, recorder.Header().Get("Location"), "scope=read+write")
}

// 测试VerifyAccessToken方法
func TestProxyOAuthServerProvider_VerifyAccessToken(t *testing.T) {
	expectedAuthInfo := &server.AuthInfo{
		ClientID: "user123",
	}

	provider := &ProxyOAuthServerProvider{
		verifyAccessToken: func(token string) (*server.AuthInfo, error) {
			return expectedAuthInfo, nil
		},
	}

	authInfo, err := provider.VerifyAccessToken("test-token")
	assert.NoError(t, err)
	assert.Equal(t, expectedAuthInfo, authInfo)
}

// 测试doFetch方法
func TestProxyOAuthServerProvider_doFetch(t *testing.T) {
	// 测试使用自定义fetch函数
	customFetchCalled := false
	provider := &ProxyOAuthServerProvider{
		fetch: func(url string, req *http.Request) (*http.Response, error) {
			customFetchCalled = true
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader("test response")),
			}, nil
		},
	}

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	resp, err := provider.doFetch(req)
	assert.NoError(t, err)
	assert.True(t, customFetchCalled)
	assert.Equal(t, 200, resp.StatusCode)
	_ = resp.Body.Close()

	// 测试使用默认HTTP客户端（会返回错误因为没有实际服务器）
	provider.fetch = nil
	_, err = provider.doFetch(req)
	// 这里会返回网络错误，因为我们没有实际的服务器
	assert.Error(t, err)
}

// 测试RevokeToken方法
func TestProxyOAuthServerProvider_RevokeToken(t *testing.T) {
	// 成功撤销令牌的测试
	provider := &ProxyOAuthServerProvider{
		endpoints: ProxyEndpoints{
			RevocationURL: "https://example.com/revoke",
		},
		fetch: func(url string, req *http.Request) (*http.Response, error) {
			// 验证请求参数
			body, _ := io.ReadAll(req.Body)
			assert.Contains(t, string(body), "token=test-token")
			assert.Contains(t, string(body), "client_id=test-client")
			assert.Contains(t, string(body), "client_secret=secret123")
			assert.Contains(t, string(body), "token_type_hint=access_token")

			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader("")),
			}, nil
		},
	}
	client := new(auth.OAuthClientInformationFull)
	client.ClientID = "test-client"
	client.ClientSecret = "secret123"

	request := auth.OAuthTokenRevocationRequest{
		Token:         "test-token",
		TokenTypeHint: "access_token",
	}

	err := provider.RevokeToken(*client, request)
	assert.NoError(t, err)

	// 测试无撤销端点的情况
	provider.endpoints.RevocationURL = ""
	err = provider.RevokeToken(*client, request)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no revocation endpoint configured")

	// 测试撤销失败的情况
	provider.endpoints.RevocationURL = "https://example.com/revoke"
	provider.fetch = func(url string, req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 400,
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	}

	err = provider.RevokeToken(*client, request)
	assert.Error(t, err)
}

// 测试ClientsStore方法（动态注册）
func TestProxyOAuthServerProvider_ClientsStore_WithRegistration(t *testing.T) {
	provider := &ProxyOAuthServerProvider{
		endpoints: ProxyEndpoints{
			RegistrationURL: "https://example.com/register",
		},
		getClient: func(clientID string) (*auth.OAuthClientInformationFull, error) {
			client := new(auth.OAuthClientInformationFull)
			client.ClientID = clientID
			return client, nil
		},
		fetch: func(url string, req *http.Request) (*http.Response, error) {
			// 模拟客户端注册响应
			clientInfo := new(auth.OAuthClientInformationFull)
			clientInfo.ClientID = "registered-client"
			body, _ := json.Marshal(clientInfo)

			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader(body)),
			}, nil
		},
	}

	store := provider.ClientsStore()
	assert.NotNil(t, store)

	// 测试注册客户端
	clientInfo := new(auth.OAuthClientInformationFull)
	clientInfo.ClientID = "new-client"

	registeredClient, err := (*store).RegisterClient(*clientInfo)
	assert.NoError(t, err)
	assert.Equal(t, "registered-client", registeredClient.ClientID)
}

// 测试ClientsStore方法（无动态注册）
func TestProxyOAuthServerProvider_ClientsStore_WithoutRegistration(t *testing.T) {
	provider := &ProxyOAuthServerProvider{
		endpoints: ProxyEndpoints{
			RegistrationURL: "",
		},
		getClient: func(clientID string) (*auth.OAuthClientInformationFull, error) {
			client := new(auth.OAuthClientInformationFull)
			if clientID == "existing-client" {
				client.ClientID = clientID
				return client, nil
			}
			return nil, fmt.Errorf("client not found")
		},
	}

	store := provider.ClientsStore()
	assert.NotNil(t, store)

	client, err := (*store).GetClient("existing-client")
	assert.NoError(t, err)
	assert.Equal(t, "existing-client", client.ClientID)

	client, err = (*store).GetClient("nonexistent-client")
	assert.Error(t, err)
}

// 测试ChallengeForAuthorizationCode方法
func TestProxyOAuthServerProvider_ChallengeForAuthorizationCode(t *testing.T) {
	provider := &ProxyOAuthServerProvider{}
	client := new(auth.OAuthClientInformationFull)
	client.ClientID = "test-client"
	challenge, err := provider.ChallengeForAuthorizationCode(*client, "auth-code-123")
	assert.NoError(t, err)
	assert.Equal(t, "", challenge) // 应该返回空字符串
}

// 测试ExchangeAuthorizationCode方法
func TestProxyOAuthServerProvider_ExchangeAuthorizationCode(t *testing.T) {
	// 成功交换授权码的测试
	provider := &ProxyOAuthServerProvider{
		endpoints: ProxyEndpoints{
			TokenURL: "https://example.com/token",
		},
		fetch: func(url string, req *http.Request) (*http.Response, error) {
			// 验证请求参数
			body, _ := io.ReadAll(req.Body)
			bodyStr := string(body)
			assert.Contains(t, bodyStr, "grant_type=authorization_code")
			assert.Contains(t, bodyStr, "client_id=test-client")
			assert.Contains(t, bodyStr, "code=auth-code-123")
			assert.Contains(t, bodyStr, "client_secret=secret123")
			assert.Contains(t, bodyStr, "code_verifier=verifier123")
			assert.Contains(t, bodyStr, "redirect_uri=https%3A%2F%2Fredirect.com%2Fcallback")

			// 模拟令牌响应
			refreshToken := "refresh-token-123"
			tokens := &auth.OAuthTokens{
				AccessToken:  "access-token-123",
				RefreshToken: &refreshToken,
				TokenType:    "Bearer",
			}
			responseBody, _ := json.Marshal(tokens)

			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader(responseBody)),
			}, nil
		},
	}
	client := new(auth.OAuthClientInformationFull)
	client.ClientID = "test-client"
	client.ClientSecret = "secret123"

	codeVerifier := "verifier123"
	redirectURI := "https://redirect.com/callback"

	tokens, err := provider.ExchangeAuthorizationCode(*client, "auth-code-123", &codeVerifier, &redirectURI, nil)
	assert.NoError(t, err)
	assert.Equal(t, "access-token-123", tokens.AccessToken)
	assert.Equal(t, "refresh-token-123", tokens.RefreshToken)
	assert.Equal(t, "Bearer", tokens.TokenType)

	// 测试无令牌端点的情况
	provider.endpoints.TokenURL = ""
	_, err = provider.ExchangeAuthorizationCode(*client, "auth-code-123", &codeVerifier, &redirectURI, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no token endpoint configured")
}

// 测试ExchangeRefreshToken方法
func TestProxyOAuthServerProvider_ExchangeRefreshToken(t *testing.T) {
	provider := &ProxyOAuthServerProvider{
		endpoints: ProxyEndpoints{
			TokenURL: "https://example.com/token",
		},
		fetch: func(url string, req *http.Request) (*http.Response, error) {
			// 验证请求参数
			body, _ := io.ReadAll(req.Body)
			bodyStr := string(body)
			assert.Contains(t, bodyStr, "grant_type=refresh_token")
			assert.Contains(t, bodyStr, "client_id=test-client")
			assert.Contains(t, bodyStr, "refresh_token=refresh-123")
			assert.Contains(t, bodyStr, "client_secret=secret123")
			assert.Contains(t, bodyStr, "scope=read+write")

			// 模拟令牌响应
			tokens := &auth.OAuthTokens{
				AccessToken: "new-access-token-123",
				TokenType:   "Bearer",
			}
			responseBody, _ := json.Marshal(tokens)

			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewReader(responseBody)),
			}, nil
		},
	}
	client := new(auth.OAuthClientInformationFull)
	client.ClientID = "test-client"
	client.ClientSecret = "secret123"

	scopes := []string{"read", "write"}
	resource, _ := url.Parse("https://api.example.com")

	tokens, err := provider.ExchangeRefreshToken(*client, "refresh-123", scopes, resource)
	assert.NoError(t, err)
	assert.Equal(t, "new-access-token-123", tokens.AccessToken)
	assert.Equal(t, "Bearer", tokens.TokenType)
}

// 测试validateOAuthTokens方法
func TestValidateOAuthTokens(t *testing.T) {
	// 有效的令牌
	validTokens := &auth.OAuthTokens{
		AccessToken: "access-token-123",
		TokenType:   "Bearer",
	}

	err := validateOAuthTokens(validTokens)
	assert.NoError(t, err)

	// 无效的令牌（缺少必需字段）
	invalidTokens := &auth.OAuthTokens{
		TokenType: "Bearer",
		// 缺少AccessToken字段
	}

	err = validateOAuthTokens(invalidTokens)
	assert.Error(t, err)
}
