// 修复后的代码
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mcp "trpc.group/trpc-go/trpc-mcp-go"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/providers"
)

const (
	testHMACSecret = "test-oauth-secret"
	testClientID   = "test-client"
	testScope      = "mcp.read mcp.write"
)

// TestOAuth2Integration tests the complete OAuth 2.1 flow with MCP server
func TestOAuth2Integration(t *testing.T) {
	// 1. 启动模拟OAuth授权服务器
	oauthServer := startMockOAuthServer(t)
	defer oauthServer.Close()

	// 2. 创建OAuth Provider
	provider := createTestOAuthProvider(oauthServer.URL)

	// 3. 启动带OAuth的MCP服务器
	mcpServerURL, cleanup := startOAuthMCPServer(t, provider)
	defer cleanup()

	// 4. 测试OAuth流程
	t.Run("BearerTokenAuth", func(t *testing.T) {
		testBearerTokenAuth(t, oauthServer.URL, mcpServerURL)
	})

	t.Run("InvalidToken", func(t *testing.T) {
		testInvalidToken(t, mcpServerURL)
	})

	// 测试授权码流程
	t.Run("AuthorizationCodeFlow", func(t *testing.T) {
		testSimpleAuthorizationCodeFlow(t, oauthServer.URL, mcpServerURL)
	})

	t.Run("TokenRefresh", func(t *testing.T) {
		testTokenRefresh(t, oauthServer.URL, mcpServerURL)
	})
}

// startMockOAuthServer 启动模拟OAuth授权服务器
func startMockOAuthServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()

	// 授权端点
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// 模拟用户授权，直接重定向到回调URL
		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		code := "test-auth-code-" + fmt.Sprintf("%d", time.Now().Unix())

		callbackURL := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, code, state)
		http.Redirect(w, r, callbackURL, http.StatusFound)
	})

	// 令牌端点
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}

		grantType := r.FormValue("grant_type")
		code := r.FormValue("code")
		refreshToken := r.FormValue("refresh_token")

		var tokenResponse map[string]interface{}

		switch grantType {
		case "authorization_code":
			if code == "" {
				http.Error(w, "Missing authorization code", http.StatusBadRequest)
				return
			}
			tokenResponse = createTokenResponse(t, "access_token", "refresh_token")

		case "refresh_token":
			if refreshToken == "" {
				http.Error(w, "Missing refresh token", http.StatusBadRequest)
				return
			}
			// 检查刷新token是否有效
			if !strings.HasPrefix(refreshToken, "test-refresh-token-") {
				http.Error(w, "Invalid refresh token", http.StatusBadRequest)
				return
			}
			tokenResponse = createTokenResponse(t, "new_access_token", "new_refresh_token")

		default:
			http.Error(w, "Unsupported grant type", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResponse)
	})

	// 客户端注册端点
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		clientInfo := map[string]interface{}{
			"client_id":     testClientID,
			"client_secret": "",
			"redirect_uris": []string{"http://localhost:5173/callback"},
			"grant_types":   []string{"authorization_code", "refresh_token"},
			"scope":         testScope,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(clientInfo)
	})

	// OAuth授权服务器元数据端点
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// 动态获取服务器URL
		baseURL := "http://" + r.Host
		metadata := map[string]interface{}{
			"issuer":                                baseURL,
			"authorization_endpoint":                baseURL + "/authorize",
			"token_endpoint":                        baseURL + "/token",
			"registration_endpoint":                 baseURL + "/register",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
			"scopes_supported":                      []string{"mcp.read", "mcp.write"},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	})

	// OpenID Connect配置端点（兼容性）
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// 动态获取服务器URL
		baseURL := "http://" + r.Host
		// 返回与OAuth元数据相同的内容
		metadata := map[string]interface{}{
			"issuer":                                baseURL,
			"authorization_endpoint":                baseURL + "/authorize",
			"token_endpoint":                        baseURL + "/token",
			"registration_endpoint":                 baseURL + "/register",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
			"scopes_supported":                      []string{"mcp.read", "mcp.write"},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	})

	server := httptest.NewServer(mux)
	t.Logf("Mock OAuth server started at: %s", server.URL)
	return server
}

// createTestOAuthProvider 创建测试用的OAuth Provider
func createTestOAuthProvider(oauthServerURL string) server.OAuthServerProvider {
	return providers.NewProxyOAuthServerProvider(providers.ProxyOptions{
		Endpoints: providers.ProxyEndpoints{
			AuthorizationURL: oauthServerURL + "/authorize",
			TokenURL:         oauthServerURL + "/token",
			RegistrationURL:  oauthServerURL + "/register",
		},
		VerifyAccessToken: func(token string) (*server.AuthInfo, error) {
			return verifyTestJWT(token)
		},
		GetClient: func(clientID string) (*auth.OAuthClientInformationFull, error) {
			return &auth.OAuthClientInformationFull{
				OAuthClientMetadata: auth.OAuthClientMetadata{
					RedirectURIs:  []string{"http://localhost:5173/callback"},
					ResponseTypes: []string{"code"},
					GrantTypes:    []string{"authorization_code", "refresh_token"},
					ClientName:    stringPtr("test-client"),
					Scope:         stringPtr(testScope),
				},
				OAuthClientInformation: auth.OAuthClientInformation{
					ClientID:     clientID,
					ClientSecret: "",
				},
			}, nil
		},
	})
}

// startOAuthMCPServer 启动带OAuth认证的MCP服务器
func startOAuthMCPServer(t *testing.T, provider server.OAuthServerProvider) (string, func()) {
	// 创建MCP服务器
	server := mcp.NewServer(
		"OAuth-Test-Server",
		"1.0.0",
		mcp.WithServerPath("/mcp"),
		mcp.WithOAuthRoutes(mcp.OAuthRoutesConfig{
			Provider:        provider,
			IssuerURL:       mustParseURL("http://localhost:3030"),
			BaseURL:         mustParseURL("http://localhost:3000"),
			ScopesSupported: []string{"mcp.read", "mcp.write"},
		}),
		mcp.WithBearerAuth(&mcp.BearerAuthConfig{
			Enabled:        true,
			RequiredScopes: []string{"mcp.read", "mcp.write"},
			Verifier: server.TokenVerifierFunc(func(ctx context.Context, token string) (server.AuthInfo, error) {
				authInfo, err := verifyTestJWT(token)
				if err != nil {
					return server.AuthInfo{}, err
				}
				return *authInfo, nil
			}),
		}),
		mcp.WithHTTPContextFunc(
			mcp.NewAuthHTTPContextFunc(
				server.TokenVerifierFunc(func(ctx context.Context, token string) (server.AuthInfo, error) {
					authInfo, err := verifyTestJWT(token)
					if err != nil {
						return server.AuthInfo{}, err
					}
					return *authInfo, nil
				}),
				mcp.ServerAuthConfig{
					Issuer:         "http://localhost:3030",
					Audience:       []string{"http://localhost:3000"},
					RequiredScopes: []string{"mcp.read", "mcp.write"},
				},
			),
		),
	)

	// 注册测试工具
	RegisterTestTools(server)

	// 创建HTTP测试服务器
	httpServer := httptest.NewServer(server.HTTPHandler())
	serverURL := httpServer.URL + "/mcp"

	t.Logf("OAuth MCP server started at: %s", serverURL)

	cleanup := func() {
		t.Log("Closing OAuth MCP server")
		httpServer.Close()
	}

	return serverURL, cleanup
}

// startCallbackServer 启动回调服务器处理OAuth授权码
func startCallbackServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()

	// 回调端点
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Callback received: %s", r.URL.RawQuery)

		// 返回成功页面
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<html>
				<head><title>Authorization Successful</title></head>
				<body>
					<h1>Authorization Successful</h1>
					<p>You can close this window now.</p>
				</body>
			</html>
		`))
	})

	server := httptest.NewServer(mux)
	t.Logf("Callback server started at: %s", server.URL)
	return server
}

// testSimpleAuthorizationCodeFlow 测试简化的授权码流程
func testSimpleAuthorizationCodeFlow(t *testing.T, oauthServerURL, mcpServerURL string) {
	// 测试授权端点是否正常工作
	t.Run("AuthorizationEndpoint", func(t *testing.T) {
		// 启动一个简单的回调服务器
		callbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Logf("Callback received: %s", r.URL.RawQuery)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))
		defer callbackServer.Close()

		// 构建授权URL，使用URL编码
		params := url.Values{}
		params.Set("client_id", testClientID)
		params.Set("response_type", "code")
		params.Set("redirect_uri", callbackServer.URL+"/callback")
		params.Set("scope", testScope)
		params.Set("state", "test-state")

		authURL := oauthServerURL + "/authorize?" + params.Encode()
		t.Logf("Testing authorization URL: %s", authURL)

		// 创建不跟随重定向的HTTP客户端
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // 不跟随重定向
			},
		}

		// 访问授权端点
		resp, err := client.Get(authURL)
		require.NoError(t, err)
		defer resp.Body.Close()

		// 应该重定向到回调URL
		assert.Equal(t, http.StatusFound, resp.StatusCode)

		// 检查重定向URL
		location := resp.Header.Get("Location")
		t.Logf("Redirect location: %s", location)
		assert.Contains(t, location, "code=")
		assert.Contains(t, location, "state=test-state")
	})

	// 测试令牌端点是否正常工作
	t.Run("TokenEndpoint", func(t *testing.T) {
		// 模拟授权码交换令牌
		formData := url.Values{}
		formData.Set("grant_type", "authorization_code")
		formData.Set("code", "test-auth-code-123")
		formData.Set("redirect_uri", "http://localhost:5173/callback")

		resp, err := http.PostForm(oauthServerURL+"/token", formData)
		require.NoError(t, err)
		defer resp.Body.Close()

		// 应该返回成功
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// 验证响应内容
		var tokenResp map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&tokenResp)
		require.NoError(t, err)

		assert.Contains(t, tokenResp, "access_token")
		assert.Contains(t, tokenResp, "refresh_token")
		assert.Equal(t, "Bearer", tokenResp["token_type"])
		assert.Equal(t, testScope, tokenResp["scope"])
	})

	// 测试OAuth元数据端点
	t.Run("OAuthMetadata", func(t *testing.T) {
		// 测试OAuth授权服务器元数据
		resp, err := http.Get(oauthServerURL + "/.well-known/oauth-authorization-server")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var metadata map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&metadata)
		require.NoError(t, err)

		assert.Equal(t, oauthServerURL, metadata["issuer"])
		assert.Contains(t, metadata, "authorization_endpoint")
		assert.Contains(t, metadata, "token_endpoint")
		assert.Contains(t, metadata, "scopes_supported")
	})
}

// testAuthorizationCodeFlow 测试授权码流程
func testAuthorizationCodeFlow(t *testing.T, oauthServerURL, mcpServerURL string) {
	// 启动回调服务器
	callbackServer := startCallbackServer(t)
	defer callbackServer.Close()

	// 创建带OAuth认证的客户端
	authFlow := mcp.AuthFlowConfig{
		ServerURL: oauthServerURL,
		ClientMetadata: auth.OAuthClientMetadata{
			ClientName:              stringPtr("test-client"),
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			TokenEndpointAuthMethod: "client_secret_post",
			RedirectURIs:            []string{callbackServer.URL + "/callback"},
			Scope:                   stringPtr(testScope),
		},
		ResourceMetadataURL: stringPtr(mcpServerURL + "/.well-known/oauth-protected-resource"),
		RedirectURL:         callbackServer.URL + "/callback",
		Scope:               stringPtr(testScope),
		OnRedirect: func(u *url.URL) error {
			t.Logf("Authorization redirect: %s", u.String())
			// 模拟用户点击授权链接，直接访问授权URL
			resp, err := http.Get(u.String())
			if err != nil {
				return fmt.Errorf("failed to access authorization URL: %w", err)
			}
			resp.Body.Close()
			return nil
		},
	}

	client, err := mcp.NewClient(
		mcpServerURL,
		mcp.Implementation{Name: "OAuth-Test-Client", Version: "1.0.0"},
		mcp.WithAuthFlow(authFlow),
	)
	require.NoError(t, err)
	defer client.Close()

	// 初始化客户端（这会触发OAuth流程）
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	initResult, err := client.Initialize(ctx, &mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.ProtocolVersion_2025_03_26,
			ClientInfo: mcp.Implementation{
				Name:    "OAuth-Test-Client",
				Version: "1.0.0",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, mcp.ProtocolVersion_2025_03_26, initResult.ProtocolVersion)

	// 测试调用需要认证的工具
	content := ExecuteTestTool(t, client, "basic-greet", map[string]interface{}{
		"name": "oauth-test",
	})

	require.Len(t, content, 1)
	textContent, ok := content[0].(mcp.TextContent)
	assert.True(t, ok)
	assert.Contains(t, textContent.Text, "Hello, oauth-test")
}

// testBearerTokenAuth 测试Bearer Token认证
func testBearerTokenAuth(t *testing.T, oauthServerURL, mcpServerURL string) {
	// 直接使用有效的JWT Token创建客户端
	validToken := createTestJWT(t, "access_token")

	// 创建HTTP头，包含Bearer Token
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+validToken)

	client, err := mcp.NewClient(
		mcpServerURL,
		mcp.Implementation{Name: "Bearer-Test-Client", Version: "1.0.0"},
		mcp.WithHTTPHeaders(headers), // 使用WithHTTPHeaders设置Authorization头
	)
	require.NoError(t, err)
	defer client.Close()

	// 初始化客户端
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = client.Initialize(ctx, &mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.ProtocolVersion_2025_03_26,
			ClientInfo: mcp.Implementation{
				Name:    "Bearer-Test-Client",
				Version: "1.0.0",
			},
		},
	})
	require.NoError(t, err)

	// 测试工具调用
	content := ExecuteTestTool(t, client, "basic-greet", map[string]interface{}{
		"name": "bearer-test",
	})

	require.Len(t, content, 1)
	textContent, ok := content[0].(mcp.TextContent)
	assert.True(t, ok)
	assert.Contains(t, textContent.Text, "Hello, bearer-test")
}

// testTokenRefresh 测试Token刷新
func testTokenRefresh(t *testing.T, oauthServerURL, mcpServerURL string) {
	// 创建一个带有刷新token的客户端
	refreshToken := "test-refresh-token-" + fmt.Sprintf("%d", time.Now().Unix())

	// 创建OAuth Provider，支持刷新token
	provider := providers.NewProxyOAuthServerProvider(providers.ProxyOptions{
		Endpoints: providers.ProxyEndpoints{
			AuthorizationURL: oauthServerURL + "/authorize",
			TokenURL:         oauthServerURL + "/token",
			RegistrationURL:  oauthServerURL + "/register",
		},
		VerifyAccessToken: func(token string) (*server.AuthInfo, error) {
			return verifyTestJWT(token)
		},
		GetClient: func(clientID string) (*auth.OAuthClientInformationFull, error) {
			return &auth.OAuthClientInformationFull{
				OAuthClientMetadata: auth.OAuthClientMetadata{
					RedirectURIs:  []string{"http://localhost:5173/callback"},
					ResponseTypes: []string{"code"},
					GrantTypes:    []string{"authorization_code", "refresh_token"},
					ClientName:    stringPtr("test-client"),
					Scope:         stringPtr(testScope),
				},
				OAuthClientInformation: auth.OAuthClientInformation{
					ClientID:     clientID,
					ClientSecret: "",
				},
			}, nil
		},
	})

	// 启动带OAuth的MCP服务器
	mcpServerURL, cleanup := startOAuthMCPServer(t, provider)
	defer cleanup()

	// 测试刷新token流程
	t.Run("RefreshTokenFlow", func(t *testing.T) {
		// 模拟刷新token请求
		refreshReq := map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": refreshToken,
		}

		// 发送刷新请求到OAuth服务器
		formData := url.Values{}
		for k, v := range refreshReq {
			formData.Set(k, v)
		}
		resp, err := http.PostForm(oauthServerURL+"/token", formData)
		require.NoError(t, err)
		defer resp.Body.Close()

		// 验证响应
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var tokenResp map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&tokenResp)
		require.NoError(t, err)

		// 验证返回的token
		assert.Contains(t, tokenResp, "access_token")
		assert.Contains(t, tokenResp, "refresh_token")
		assert.Equal(t, "Bearer", tokenResp["token_type"])
		assert.Equal(t, testScope, tokenResp["scope"])

		// 验证新的access token是否有效
		newAccessToken, ok := tokenResp["access_token"].(string)
		require.True(t, ok)

		// 使用新的access token创建客户端
		headers := make(http.Header)
		headers.Set("Authorization", "Bearer "+newAccessToken)

		client, err := mcp.NewClient(
			mcpServerURL,
			mcp.Implementation{Name: "Refresh-Test-Client", Version: "1.0.0"},
			mcp.WithHTTPHeaders(headers),
		)
		require.NoError(t, err)
		defer client.Close()

		// 测试使用新token调用工具
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, err = client.Initialize(ctx, &mcp.InitializeRequest{
			Params: mcp.InitializeParams{
				ProtocolVersion: mcp.ProtocolVersion_2025_03_26,
				ClientInfo: mcp.Implementation{
					Name:    "Refresh-Test-Client",
					Version: "1.0.0",
				},
			},
		})
		require.NoError(t, err)

		// 测试工具调用
		content := ExecuteTestTool(t, client, "basic-greet", map[string]interface{}{
			"name": "refresh-test",
		})

		require.Len(t, content, 1)
		textContent, ok := content[0].(mcp.TextContent)
		assert.True(t, ok)
		assert.Contains(t, textContent.Text, "Hello, refresh-test")
	})

	// 测试无效刷新token
	t.Run("InvalidRefreshToken", func(t *testing.T) {
		invalidRefreshReq := map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": "invalid-refresh-token",
		}

		formData := url.Values{}
		for k, v := range invalidRefreshReq {
			formData.Set(k, v)
		}
		resp, err := http.PostForm(oauthServerURL+"/token", formData)
		require.NoError(t, err)
		defer resp.Body.Close()

		// 应该返回错误（400 Bad Request）
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// testInvalidToken 测试无效Token
func testInvalidToken(t *testing.T, mcpServerURL string) {
	// 使用无效Token创建客户端
	invalidToken := "invalid.jwt.token"

	// 创建HTTP头，包含无效的Bearer Token
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+invalidToken)

	client, err := mcp.NewClient(
		mcpServerURL,
		mcp.Implementation{Name: "Invalid-Token-Client", Version: "1.0.0"},
		mcp.WithHTTPHeaders(headers), // 使用WithHTTPHeaders设置Authorization头
	)
	require.NoError(t, err)
	defer client.Close()

	// 尝试初始化客户端，应该失败
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = client.Initialize(ctx, &mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.ProtocolVersion_2025_03_26,
			ClientInfo: mcp.Implementation{
				Name:    "Invalid-Token-Client",
				Version: "1.0.0",
			},
		},
	})

	// 应该返回认证错误
	assert.Error(t, err)
	// 检查是否包含认证相关的错误信息
	errorMsg := err.Error()
	assert.True(t,
		strings.Contains(errorMsg, "unauthorized") ||
			strings.Contains(errorMsg, "401") ||
			strings.Contains(errorMsg, "authentication") ||
			strings.Contains(errorMsg, "auth"),
		"Expected authentication error, got: %s", errorMsg)
}

// 辅助函数

func createTokenResponse(t *testing.T, accessToken, refreshToken string) map[string]interface{} {
	return map[string]interface{}{
		"access_token":  createTestJWT(t, accessToken),
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"scope":         testScope,
	}
}

func createTestJWT(t *testing.T, tokenType string) string {
	claims := jwt.MapClaims{
		"iss":        "http://localhost:3030",
		"aud":        []string{"http://localhost:3000"},
		"sub":        testClientID,
		"scope":      "mcp.read mcp.write", // 确保作用域正确
		"iat":        time.Now().Unix(),
		"exp":        time.Now().Add(time.Hour).Unix(),
		"token_type": tokenType,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(testHMACSecret))
	require.NoError(t, err)
	return signedToken
}

func verifyTestJWT(tokenString string) (*server.AuthInfo, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(testHMACSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		scopes := []string{}
		if scope, ok := claims["scope"].(string); ok {
			// 将空格分隔的作用域字符串转换为切片
			scopes = strings.Fields(scope)
		}

		return &server.AuthInfo{
			ClientID: claims["sub"].(string),
			Scopes:   scopes,
		}, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func stringPtr(s string) *string {
	return &s
}

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
