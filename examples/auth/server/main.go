package main

import (
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

	// 先启动一个简单的 OAuth 模拟服务器在端口 3030
	go startMockOAuthServer()

	// 等待模拟服务器启动
	time.Sleep(2 * time.Second)

	// 测试模拟服务器是否就绪
	resp, err := http.Get("http://localhost:3030/authorize?test=1")
	if err != nil {
		log.Fatalf("Mock OAuth server not ready: %v", err)
	}
	resp.Body.Close()
	log.Println("Mock OAuth server is ready")

	// 创建 Proxy OAuth Provider，代理到模拟的 OAuth 服务器
	provider := providers.NewProxyOAuthServerProvider(providers.ProxyOptions{
		Endpoints: providers.ProxyEndpoints{
			AuthorizationURL: "http://localhost:3030/authorize",
			TokenURL:         "http://localhost:3030/token",
			RevocationURL:    "http://localhost:3030/revoke",
			RegistrationURL:  "http://localhost:3030/register",
		},
		VerifyAccessToken: func(token string) (*server.AuthInfo, error) {
			// 验证访问令牌
			log.Printf("Verifying access token: %s", token)
			return &server.AuthInfo{
				Token:    token,
				ClientID: "test-client-id",
				Scopes:   []string{"mcp.read", "mcp.write"},
			}, nil
		},
		GetClient: func(clientID string) (*auth.OAuthClientInformationFull, error) {
			// 返回客户端信息
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
		// 添加自定义 Fetch 函数进行调试
		Fetch: func(url string, req *http.Request) (*http.Response, error) {
			log.Printf("Custom Fetch: Making request to %s", url)
			log.Printf("Custom Fetch: Method: %s", req.Method)
			log.Printf("Custom Fetch: Headers:")
			for key, values := range req.Header {
				log.Printf("  %s: %v", key, values)
			}

			// 读取请求体进行调试（需要重新创建）
			if req.Body != nil {
				bodyBytes, err := io.ReadAll(req.Body)
				if err == nil {
					log.Printf("Custom Fetch: Body: %s", string(bodyBytes))
					// 重新创建请求体
					req.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
				}
			}

			client := &http.Client{Timeout: 10 * time.Second}
			return client.Do(req)
		},
	})

	// 启动 MCP Server，使用代理 OAuth Provider
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
	)

	log.Println("OAuth server is listening on :3000")
	log.Println("Mock OAuth server is listening on :3030")
	log.Println("Authorization endpoint: http://localhost:3000/authorize")
	log.Println("Token endpoint: http://localhost:3000/token")

	if err := mcpServer.Start(); err != nil {
		log.Fatal(err)
	}
}

// 启动一个简单的模拟 OAuth 服务器在端口 3030
func startMockOAuthServer() {
	mux := http.NewServeMux()

	// 存储授权码
	var authCode = "mock_auth_code_12345"
	var accessToken = "mock_access_token_67890"

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
		w.WriteHeader(http.StatusOK)
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

// getFormValue 从 url.Values 中安全地获取第一个值
func getFormValue(values url.Values, key string) string {
	if vals, ok := values[key]; ok && len(vals) > 0 {
		return vals[0]
	}
	return ""
}
