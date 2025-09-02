package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	mcp "trpc.group/trpc-go/trpc-mcp-go"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/providers"
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
			RegistrationURL:  "http://localhost:3030/register",
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
					ClientSecret: "",
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
		mcp.WithOAuthRoutes(mcp.OAuthRoutesConfig{
			Provider:        provider,
			IssuerURL:       mustURL("http://localhost:3000"),
			BaseURL:         mustURL("http://localhost:3000"),
			ScopesSupported: []string{"mcp.read", "mcp.write"},

			// 可选：令牌刷新时帮助识别 client_id（比如从 RT 里解出来）
			ResolveClientIDFromRT: func(rt string) (string, bool) {
				cid := tryParseClientIDFromRefreshToken(rt) // 伪代码
				return cid, cid != ""
			},
		}),

		mcp.WithBearerAuth(&mcp.BearerAuthConfig{
			Enabled:        true,
			RequiredScopes: []string{"mcp.read"},
			Verifier: server.TokenVerifierFunc(func(ctx context.Context, token string) (server.AuthInfo, error) {
				log.Printf("DEBUG: Verifying token: %s", token[:20]+"...")
				ai, err := mockVerifyJWT(token)
				if err != nil {
					log.Printf("DEBUG: Token verification failed: %v", err)
					return server.AuthInfo{}, err
				}

				log.Printf("DEBUG Verifier->return: client_id=%s scopes=%v", ai.ClientID, ai.Scopes)
				return ai, nil
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
	observing := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("ROUTING: hit path=%s", r.URL.Path)
		mcpServer.Handler().ServeHTTP(w, r)
	})

	log.Println("== DEBUG: wrapping :3000 with observing handler ==")
	if err := http.ListenAndServe(":3000", observing); err != nil {
		log.Fatal(err)
	}
}

// 启动一个简单的模拟 OAuth 服务器在端口 3030
func startMockOAuthServer() {
	mux := http.NewServeMux()

	// 存储授权码
	var authCode = "mock_auth_code_12345"

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

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Mock OAuth: Token exchange request received")
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// 统一解析表单
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}

		grantType := r.FormValue("grant_type")

		// 小工具：签发一个“无签名”的伪 JWT，便于调试
		makeJWT := func(payload map[string]any) string {
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
			b, _ := json.Marshal(payload)
			body := base64.RawURLEncoding.EncodeToString(b)
			return header + "." + body + "."
		}

		switch grantType {
		case "authorization_code":
			clientID := r.FormValue("client_id")
			clientSecret := r.FormValue("client_secret") // 如果传了，我们当保密客户端处理
			code := r.FormValue("code")
			redirectURI := r.FormValue("redirect_uri")
			codeVerifier := r.FormValue("code_verifier")

			// 基本参数校验
			if clientID == "" || code == "" || redirectURI == "" || codeVerifier == "" {
				http.Error(w, "Missing required parameters for authorization_code", http.StatusBadRequest)
				return
			}

			// 若你要演示“保密客户端”，这里可以校验 secret；没传 secret 就按 public 走
			if clientSecret != "" {
				if clientSecret != "test-secret" { // 按你的演示值校验
					http.Error(w, "Invalid client_secret", http.StatusUnauthorized)
					return
				}
			}

			// 颁发 token（演示值）
			accessToken := makeJWT(map[string]any{
				"client_id": clientID,
				"scope":     "mcp.read",
				"exp":       time.Now().Add(1 * time.Hour).Unix(),
			})
			refreshToken := makeJWT(map[string]any{
				"client_id": clientID,
				"typ":       "refresh",
				"exp":       time.Now().Add(24 * time.Hour).Unix(),
			})

			resp := map[string]any{
				"access_token":  accessToken,
				"token_type":    "Bearer",
				"expires_in":    3600,
				"scope":         "mcp.read",
				"refresh_token": refreshToken,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

		case "refresh_token":
			refreshToken := r.FormValue("refresh_token")
			if refreshToken == "" {
				http.Error(w, "Missing refresh_token", http.StatusBadRequest)
				return
			}

			// 可选：若传了 client_id/client_secret，这里也可验证；不传则按 public 刷新
			clientID := r.FormValue("client_id")
			clientSecret := r.FormValue("client_secret")
			if clientSecret != "" && clientSecret != "test-secret" {
				http.Error(w, "Invalid client_secret", http.StatusUnauthorized)
				return
			}

			// 从 RT 里尽力解析 client_id（便于日志 & 回显）
			if clientID == "" {
				parts := strings.Split(refreshToken, ".")
				if len(parts) == 3 {
					if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
						var m map[string]any
						if json.Unmarshal(payload, &m) == nil {
							if v, ok := m["client_id"].(string); ok {
								clientID = v
							}
						}
					}
				}
			}
			if clientID == "" {
				// 实在拿不到就给个演示用 id（也可以改为 400）
				clientID = "public-client"
			}

			// 颁发新 token
			accessToken := makeJWT(map[string]any{
				"client_id": clientID,
				"scope":     "mcp.read",
				"exp":       time.Now().Add(1 * time.Hour).Unix(),
			})
			newRefreshToken := makeJWT(map[string]any{
				"client_id": clientID,
				"typ":       "refresh",
				"exp":       time.Now().Add(24 * time.Hour).Unix(),
			})

			resp := map[string]any{
				"access_token":  accessToken,
				"token_type":    "Bearer",
				"expires_in":    3600,
				"scope":         "mcp.read",
				"refresh_token": newRefreshToken,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

		default:
			http.Error(w, "unsupported_grant_type", http.StatusBadRequest)
			return
		}
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
	log.Printf("DEBUG mockVerifyJWT: payload b64=%s json=%s", parts[1], string(payloadJSON))
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

	log.Printf("DEBUG mockVerifyJWT: client_id=%s scopes=%v", clientID, scopes)
	return server.AuthInfo{
		Token:     token,
		ClientID:  clientID,
		Scopes:    scopes,
		ExpiresAt: &exp,
		Extra:     payload,
	}, nil
}

// tryParseClientIDFromRefreshToken 解析 refresh_token 中的 client_id
func tryParseClientIDFromRefreshToken(refreshToken string) string {
	// 假设 refresh_token 是无签名的 JWT（header.payload.signature）
	parts := strings.Split(refreshToken, ".")
	if len(parts) != 3 {
		return "" // token 格式不正确
	}

	// 解码 JWT 的 payload 部分（中间的部分）
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "" // 解码失败
	}

	// 解析 JSON 数据（payload）
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return "" // JSON 解析失败
	}

	// 从 payload 中提取 client_id
	clientID, ok := data["client_id"].(string)
	if !ok {
		return "" // 没有找到 client_id
	}

	return clientID
}
