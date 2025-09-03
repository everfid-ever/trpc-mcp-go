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

	"github.com/golang-jwt/jwt/v5"
	mcp "trpc.group/trpc-go/trpc-mcp-go"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/providers"
)

const hmacSecret = "demo-shared-secret"

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
			log.Printf("Verifying access token: %s", token[:20]+"...")
			ai, err := mockVerifyJWT(token)
			if err != nil {
				log.Printf("Token verification failed: %v", err)
				return nil, err
			}
			log.Printf("Token verified successfully: client_id=%s, scopes=%v", ai.ClientID, ai.Scopes)
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
					ClientSecret: "", // 公共客户端，无密钥
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
			IssuerURL:       mustURL("http://localhost:3030"),
			BaseURL:         mustURL("http://localhost:3000"),
			ScopesSupported: []string{"mcp.read", "mcp.write"},

			// 可选：令牌刷新时帮助识别 client_id（比如从 RT 里解出来）
			ResolveClientIDFromRT: func(rt string) (string, bool) {
				cid := tryParseClientIDFromRefreshToken(rt)
				return cid, cid != ""
			},
		}),
		mcp.WithOAuthMetadata(mcp.OAuthMetadataConfig{
			ResourceServerURL: mustURL("http://localhost:3000"),
			ScopesSupported:   []string{"mcp.read", "mcp.write"},
			ResourceName:      strPtr("MCP Server"),
		}),
		mcp.WithBearerAuth(&mcp.BearerAuthConfig{
			Enabled:        true,
			RequiredScopes: []string{"mcp.read"},
			Verifier: server.TokenVerifierFunc(func(ctx context.Context, token string) (server.AuthInfo, error) {
				log.Printf("Bearer auth: Verifying token: %s", token[:20]+"...")
				ai, err := mockVerifyJWT(token)
				if err != nil {
					log.Printf("Bearer auth: Token verification failed: %v", err)
					return server.AuthInfo{}, err
				}

				log.Printf("Bearer auth: Token verified - client_id=%s scopes=%v", ai.ClientID, ai.Scopes)
				return ai, nil
			}),
		}),
		mcp.WithAudit(&mcp.AuditConfig{
			Enabled:             true,
			Level:               "detailed",
			HashSensitiveData:   true,
			IncludeRequestBody:  true,
			IncludeResponseBody: true,
			EndpointPatterns:    []string{"/mcp/", "/authorize", "/token"},
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
		log.Printf("ROUTING: %s %s", r.Method, r.URL.Path)
		mcpServer.Handler().ServeHTTP(w, r)
	})

	log.Println("MCP Server starting on :3000")
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
		log.Printf("Mock OAuth: Authorization request: %s %s", r.Method, r.URL.RawQuery)

		// 处理测试请求
		if r.URL.Query().Get("test") != "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
			return
		}

		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		clientID := r.URL.Query().Get("client_id")
		codeChallenge := r.URL.Query().Get("code_challenge")
		scope := r.URL.Query().Get("scope")

		log.Printf("Mock OAuth: client_id=%s, scope=%s, code_challenge=%s", clientID, scope, codeChallenge[:10]+"...")

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

	// /token：支持 authorization_code 与 refresh_token，签发 HS256 的 JWT
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
		log.Printf("Mock OAuth: Grant type: %s", grantType)

		// 便捷函数：签发 HS256 JWT
		signJWT := func(claims jwt.MapClaims) (string, error) {
			tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			signed, err := tok.SignedString([]byte(hmacSecret))
			if err != nil {
				return "", err
			}
			log.Printf("Mock OAuth: Signed token with claims: %+v", claims)
			return signed, nil
		}

		switch grantType {
		case "authorization_code":
			clientID := r.FormValue("client_id")
			code := r.FormValue("code")
			redirectURI := r.FormValue("redirect_uri")
			codeVerifier := r.FormValue("code_verifier")

			log.Printf("Mock OAuth: Code exchange - client_id=%s, code=%s, redirect_uri=%s",
				clientID, code, redirectURI)

			// 基本参数校验
			if clientID == "" || code == "" || redirectURI == "" || codeVerifier == "" {
				http.Error(w, "Missing required parameters for authorization_code", http.StatusBadRequest)
				return
			}

			now := time.Now()
			// 颁发 access_token（带 iss/aud/iat/exp）
			accessToken, err := signJWT(jwt.MapClaims{
				"iss":       "http://localhost:3030",
				"aud":       "http://localhost:3000",
				"iat":       now.Unix(),
				"exp":       now.Add(1 * time.Hour).Unix(),
				"client_id": clientID,
				"scope":     "mcp.read",
			})
			if err != nil {
				log.Printf("Mock OAuth: Failed to sign access token: %v", err)
				http.Error(w, "failed to sign access token", http.StatusInternalServerError)
				return
			}

			// 颁发 refresh_token
			refreshToken, err := signJWT(jwt.MapClaims{
				"iss":       "http://localhost:3030",
				"aud":       "http://localhost:3000",
				"iat":       now.Unix(),
				"exp":       now.Add(24 * time.Hour).Unix(),
				"client_id": clientID,
				"typ":       "refresh",
			})
			if err != nil {
				log.Printf("Mock OAuth: Failed to sign refresh token: %v", err)
				http.Error(w, "failed to sign refresh token", http.StatusInternalServerError)
				return
			}

			resp := map[string]any{
				"access_token":  accessToken,
				"token_type":    "Bearer",
				"expires_in":    3600,
				"scope":         "mcp.read",
				"refresh_token": refreshToken,
			}

			log.Printf("Mock OAuth: Returning token response")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

		case "refresh_token":
			rt := r.FormValue("refresh_token")
			if rt == "" {
				http.Error(w, "Missing refresh_token", http.StatusBadRequest)
				return
			}

			log.Printf("Mock OAuth: Refreshing token")

			// 解析并校验 RT（HS256）
			parsed, err := jwt.Parse(rt, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				return []byte(hmacSecret), nil
			})
			if err != nil || !parsed.Valid {
				log.Printf("Mock OAuth: Invalid refresh token: %v", err)
				http.Error(w, "invalid refresh_token", http.StatusUnauthorized)
				return
			}
			claims, ok := parsed.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, "invalid refresh_token claims", http.StatusUnauthorized)
				return
			}

			// 从 RT claims 提取 client_id（没有就退回 public-client）
			clientID, _ := claims["client_id"].(string)
			if clientID == "" {
				clientID = "public-client"
			}

			now := time.Now()
			// 新 access_token
			newAT, err := signJWT(jwt.MapClaims{
				"iss":       "http://localhost:3030",
				"aud":       "http://localhost:3000",
				"iat":       now.Unix(),
				"exp":       now.Add(1 * time.Hour).Unix(),
				"client_id": clientID,
				"scope":     "mcp.read",
			})
			if err != nil {
				http.Error(w, "failed to sign access token", http.StatusInternalServerError)
				return
			}

			// 新 refresh_token（可轮换）
			newRT, err := signJWT(jwt.MapClaims{
				"iss":       "http://localhost:3030",
				"aud":       "http://localhost:3000",
				"iat":       now.Unix(),
				"exp":       now.Add(24 * time.Hour).Unix(),
				"client_id": clientID,
				"typ":       "refresh",
			})
			if err != nil {
				http.Error(w, "failed to sign refresh token", http.StatusInternalServerError)
				return
			}

			resp := map[string]any{
				"access_token":  newAT,
				"token_type":    "Bearer",
				"expires_in":    3600,
				"scope":         "mcp.read",
				"refresh_token": newRT,
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

	// 授权服务器元数据（RFC 8414）
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Mock OAuth: Metadata request")
		meta := map[string]any{
			"issuer":                                "http://localhost:3030",
			"authorization_endpoint":                "http://localhost:3030/authorize",
			"token_endpoint":                        "http://localhost:3030/token",
			"registration_endpoint":                 "http://localhost:3030/register",
			"revocation_endpoint":                   "http://localhost:3030/revoke",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
			"scopes_supported":                      []string{"mcp.read", "mcp.write"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meta)
	})

	// 兼容 OIDC 发现（很多客户端会同时尝试这个路径）
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Mock OAuth: OIDC configuration request")
		cfg := map[string]any{
			"issuer":                                "http://localhost:3030",
			"authorization_endpoint":                "http://localhost:3030/authorize",
			"token_endpoint":                        "http://localhost:3030/token",
			"registration_endpoint":                 "http://localhost:3030/register",
			"revocation_endpoint":                   "http://localhost:3030/revoke",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
			"scopes_supported":                      []string{"mcp.read", "mcp.write"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	})

	server := &http.Server{
		Addr:    ":3030",
		Handler: mux,
	}

	log.Println("Mock OAuth server starting on http://localhost:3030")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("Mock OAuth server error: %v", err)
	}
}

func mockVerifyJWT(token string) (server.AuthInfo, error) {
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(hmacSecret), nil
	})
	if err != nil || !parsed.Valid {
		return server.AuthInfo{}, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return server.AuthInfo{}, fmt.Errorf("invalid claims")
	}

	clientID, _ := claims["client_id"].(string)
	scopeStr, _ := claims["scope"].(string)
	scopes := []string{}
	if scopeStr != "" {
		scopes = strings.Split(scopeStr, " ")
	}
	var expPtr *int64
	if v, ok := claims["exp"].(float64); ok {
		vv := int64(v)
		expPtr = &vv
	}

	return server.AuthInfo{
		Token:     token,
		ClientID:  clientID,
		Scopes:    scopes,
		ExpiresAt: expPtr,
		Extra:     claims,
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
