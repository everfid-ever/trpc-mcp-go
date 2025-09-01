package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	mcp "trpc.group/trpc-go/trpc-mcp-go"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/providers"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/router"
)

func strPtr(s string) *string {
	return &s
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func main() {
	log.Println("Starting OAuth server...")

	// 先启动模拟OAuth服务器
	go startMockOAuthServer()
	time.Sleep(2 * time.Second)

	// 测试模拟服务器
	resp, err := http.Get("http://localhost:3030/authorize?test=1")
	if err != nil {
		log.Fatalf("Mock OAuth server not ready: %v", err)
	}
	resp.Body.Close()
	log.Println("Mock OAuth server is ready")

	// 创建OAuth Provider
	provider := providers.NewProxyOAuthServerProvider(providers.ProxyOptions{
		Endpoints: providers.ProxyEndpoints{
			AuthorizationURL: "http://localhost:3030/authorize",
			TokenURL:         "http://localhost:3030/token",
			RevocationURL:    "http://localhost:3030/revoke",
			//RegistrationURL:  "http://localhost:3030/register",
		},

		VerifyAccessToken: func(token string) (*server.AuthInfo, error) {
			ai, err := mockVerifyJWT(token)
			if err != nil {
				return nil, err
			}
			return &ai, nil
		},

		GetClient: func(clientID string) (*auth.OAuthClientInformationFull, error) {
			log.Printf("Getting client info for: %s", clientID)
			return &auth.OAuthClientInformationFull{
				OAuthClientMetadata: auth.OAuthClientMetadata{
					RedirectURIs:  []string{"http://localhost:5173/callback"},
					ResponseTypes: []string{"code"},
					GrantTypes:    []string{"authorization_code", "refresh_token"},
					ClientName:    strPtr("demo-client"),
					Scope:         strPtr("mcp.read mcp.write"),
				},
				OAuthClientInformation: auth.OAuthClientInformation{
					ClientID:     clientID,
					ClientSecret: "test-secret",
				},
			}, nil
		},
	})

	// 创建并启动MCP服务器
	mcpServer := mcp.NewServer(
		"Auth-Example-Server",
		"1.0.0",
		mcp.WithServerAddress(":3000"),
		mcp.WithServerPath("/mcp"),
		mcp.WithOAuthRoutes(router.AuthRouterOptions{
			Provider:        provider,
			IssuerUrl:       mustURL("http://localhost:3000"),
			BaseUrl:         mustURL("http://localhost:3000"),
			ScopesSupported: []string{"mcp.read", "mcp.write"},
		}),

		mcp.WithBearerAuth(&mcp.BearerAuthConfig{
			Enabled:        true,
			RequiredScopes: []string{"mcp.read"},
			Verifier: server.TokenVerifierFunc(func(ctx context.Context, token string) (server.AuthInfo, error) {
				// 直接复用你原来 main.go 里的 mock 逻辑：
				parts := strings.Split(token, ".")
				if len(parts) < 2 {
					return server.AuthInfo{}, fmt.Errorf("invalid token format")
				}
				payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
				if err != nil {
					return server.AuthInfo{}, fmt.Errorf("failed to decode JWT payload: %w", err)
				}
				var payload map[string]interface{}
				if err := json.Unmarshal(payloadJSON, &payload); err != nil {
					return server.AuthInfo{}, fmt.Errorf("failed to unmarshal JWT payload: %w", err)
				}

				clientID, _ := payload["client_id"].(string)
				scopeStr, _ := payload["scope"].(string)
				scopes := []string{}
				if scopeStr != "" {
					scopes = strings.Split(scopeStr, " ")
				}

				exp := time.Now().Add(1 * time.Hour).Unix()

				return server.AuthInfo{
					Token:     token,
					ClientID:  clientID,
					Scopes:    scopes,
					ExpiresAt: &exp,
					Extra:     payload,
				}, nil
			}),
		}),

		mcp.WithAudit(&mcp.AuditConfig{
			Enabled:             true,
			Level:               "detailed",
			HashSensitiveData:   true,
			IncludeRequestBody:  true,
			IncludeResponseBody: true,
			EndpointPatterns:    []string{"/mcp/", "/oauth2/", "/authorize", "/token"},
			ExcludePatterns:     []string{"/healthz"},
		}),
	)

	greetTool := mcp.NewTool("greet",
		mcp.WithDescription("A simple greeting tool (OAuth protected)"),
		mcp.WithString("name", mcp.Description("Name to greet")))

	mcpServer.RegisterTool(greetTool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name, _ := req.Params.Arguments["name"].(string)
		if name == "" {
			name = "World"
		}

		return mcp.NewTextResult(fmt.Sprintf("Hello, %s! (Authenticated via OAuth)", name)), nil
	})

	// 直接启动MCP服务器
	if err := mcpServer.Start(); err != nil {
		log.Fatal(err)
	}
}

// 启动一个简单的模拟 OAuth 服务器在端口 3030
func startMockOAuthServer() {
	mux := http.NewServeMux()

	// 存储授权码
	var authCode = "mock_auth_code_12345"
	// 生成一个模拟 JWT: header.payload.signature
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"client_id":"test-client-id","scope":"mcp.read mcp.write"}`))
	signature := "mocksignature" // 不做签名校验

	accessToken := fmt.Sprintf("%s.%s.%s", header, payload, signature)

	// 授权端点
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Mock OAuth: Authorization request received: %s", r.URL.RawQuery)

		// 处理测试请求
		if r.URL.Query().Get("test") != "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
			return
		}

		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")

		if redirectURI == "" {
			http.Error(w, "Missing redirect_uri", http.StatusBadRequest)
			return
		}

		// 构建重定向 URL
		redirectURL := redirectURI + "?code=" + authCode
		if state != "" {
			redirectURL += "&state=" + state
		}

		log.Printf("Mock OAuth: Redirecting to %s", redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusFound)
	})

	// 模拟 OAuth 服务器的令牌端点
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Mock OAuth: Token exchange request received")

		if r.Method != "POST" {
			log.Printf("Mock OAuth: Method not allowed: %s", r.Method)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// 读取原始请求体进行调试
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Mock OAuth: Error reading body: %v", err)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_request",
				"error_description": fmt.Sprintf("Failed to read body: %v", err),
			})
			return
		}

		log.Printf("Mock OAuth: Raw request body: %s", string(body))

		// 手动解析 URL 编码的表单数据
		formData, err := url.ParseQuery(string(body))
		if err != nil {
			log.Printf("Mock OAuth: Error parsing form data: %v", err)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_request",
				"error_description": fmt.Sprintf("Failed to parse form data: %v", err),
			})
			return
		}

		// 打印所有接收到的参数进行调试
		log.Printf("Mock OAuth: Parsed form parameters:")
		for key, values := range formData {
			log.Printf("  %s: %v", key, values)
		}

		// 提取参数并进行验证
		code := formData.Get("code")
		clientID := formData.Get("client_id")
		clientSecret := formData.Get("client_secret")
		redirectURI := formData.Get("redirect_uri")
		codeVerifier := formData.Get("code_verifier")

		if code != "mock_auth_code_12345" {
			log.Printf("Mock OAuth: Invalid authorization code: %s", code)
			http.Error(w, "Invalid authorization code", http.StatusBadRequest)
			return
		}

		if clientID != "test-client-id" {
			log.Printf("Mock OAuth: Invalid client ID: %s", clientID)
			http.Error(w, "Invalid client ID", http.StatusBadRequest)
			return
		}

		if clientSecret != "test-secret" {
			log.Printf("Mock OAuth: Invalid client secret: %s", clientSecret)
			http.Error(w, "Invalid client secret", http.StatusBadRequest)
			return
		}

		if redirectURI != "http://localhost:5173/callback" {
			log.Printf("Mock OAuth: Invalid redirect URI: %s", redirectURI)
			http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
			return
		}

		// 验证 PKCE (code_verifier)
		if codeVerifier == "" {
			log.Printf("Mock OAuth: Missing code verifier")
			http.Error(w, "Missing code verifier", http.StatusBadRequest)
			return
		}

		// 返回令牌
		response := map[string]interface{}{
			"access_token":  accessToken,
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "mock_refresh_token_99999",
			"scope":         "mcp.read mcp.write",
			"client_id":     "test-client-id",
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Mock OAuth: Error encoding response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		log.Printf("Mock OAuth: Access token issued successfully")
	})

	// 撤销端点（可选）
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Mock OAuth: Token revocation request received")
		w.WriteHeader(http.StatusOK)
	})

	// 注册端点（可选）
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Mock OAuth: Client registration request received")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"client_id":      "test-client-id",
			"client_secret":  "test-secret",
			"client_name":    "demo-client",
			"scope":          "mcp.read mcp.write",
			"redirect_uris":  []string{"http://localhost:5173/callback"},
			"grant_types":    []string{"authorization_code", "refresh_token"},
			"response_types": []string{"code"},
		})
	})

	// 添加一个通用的请求日志中间件
	loggingMux := http.NewServeMux()
	loggingMux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Mock OAuth: Incoming request: %s %s", r.Method, r.URL.Path)
		log.Printf("Mock OAuth: Headers:")
		for key, values := range r.Header {
			log.Printf("  %s: %v", key, values)
		}
		mux.ServeHTTP(w, r)
	}))

	server := &http.Server{
		Addr:    ":3030",
		Handler: loggingMux,
	}

	log.Println("Mock OAuth server starting on http://localhost:3030")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("Mock OAuth server error: %v", err)
	}
}

func mockVerifyJWT(token string) (server.AuthInfo, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return server.AuthInfo{}, fmt.Errorf("invalid token format")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return server.AuthInfo{}, fmt.Errorf("failed to decode JWT payload: %w", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return server.AuthInfo{}, fmt.Errorf("failed to unmarshal JWT payload: %w", err)
	}

	clientID, _ := payload["client_id"].(string)
	scopeStr, _ := payload["scope"].(string)
	var scopes []string
	if scopeStr != "" {
		scopes = strings.Split(scopeStr, " ")
	}
	exp := time.Now().Add(1 * time.Hour).Unix()

	return server.AuthInfo{
		Token:     token,
		ClientID:  clientID,
		Scopes:    scopes,
		ExpiresAt: &exp,
		Extra:     payload,
	}, nil
}
