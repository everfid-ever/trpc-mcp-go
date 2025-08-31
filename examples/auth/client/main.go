package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	mcp "trpc.group/trpc-go/trpc-mcp-go"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/client"
)

func strPtr(s string) *string { return &s }

var (
	codeCh       = make(chan string, 1) // 存放授权 code
	codeVerifier string                 // 存放PKCE验证码
)

func main() {
	log.Println("Starting OAuth client...")

	// 生成PKCE参数
	verifier, challenge := generatePKCE()
	codeVerifier = verifier // 保存供token交换时使用

	// 构造授权 URL（添加PKCE参数）
	authURL := "http://localhost:3000/authorize" +
		"?response_type=code" +
		"&client_id=test-client-id" +
		"&redirect_uri=http://localhost:5173/callback" +
		"&scope=mcp.read" +
		"&code_challenge=" + url.QueryEscape(challenge) +
		"&code_challenge_method=S256"

	// 打印授权 URL，用户需要在浏览器中访问
	log.Println("Please open the following URL in your browser to authorize:")
	log.Println(authURL)

	// 启动回调服务器，等待获取授权 code
	go startCallbackServer()

	// 打印消息，等待授权
	log.Println("Waiting for browser callback...")

	// 等待用户输入授权 code
	code := <-codeCh // 阻塞直到拿到 code
	log.Println("Authorization code received:", code)

	// 使用授权 code 交换 access_token
	token, err := exchangeToken("http://localhost:3000/token", code, "http://localhost:5173/callback")
	if err != nil {
		log.Fatalf("Error exchanging token: %v", err)
	}

	log.Println("Received access token:", token.AccessToken)

	// 创建 OAuth provider 并设置 tokens
	oauthProvider := client.NewInMemoryOAuthClientProvider(
		"http://localhost:5173/callback",
		auth.OAuthClientMetadata{
			ClientName: strPtr("demo-client"),
			GrantTypes: []string{"authorization_code", "refresh_token"},
		},
		nil, // onRedirect callback
	)

	// 保存获取到的 tokens
	if err := oauthProvider.SaveTokens(*token); err != nil {
		log.Fatalf("Failed to save tokens: %v", err)
	}

	// 创建 MCP 客户端
	log.Println("Initializing MCP client...")
	ctx := context.Background()
	c, err := mcp.NewClient(
		"http://localhost:3000/mcp", // 这里改成你实际的 MCP 服务地址
		mcp.Implementation{Name: "demo", Version: "0.1.0"},
		mcp.WithOAuthClientProvider(oauthProvider), // 使用 OAuth provider 而不是直接的 access token
	)
	if err != nil {
		log.Fatal("Failed to create MCP client: ", err)
	}

	// 执行 MCP 初始化
	if _, err := c.Initialize(ctx, nil); err != nil {
		log.Printf("Initialization failed: %v", err)
	} else {
		log.Println("MCP client initialized successfully!")
	}
}

// generatePKCE 生成PKCE挑战参数
func generatePKCE() (verifier, challenge string) {
	// 生成32字节随机数作为code_verifier
	bytes := make([]byte, 32)
	rand.Read(bytes)
	verifier = base64.RawURLEncoding.EncodeToString(bytes)

	// 用SHA256哈希生成code_challenge
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])

	return verifier, challenge
}

// exchangeToken 向 /token 端点换取 access_token（添加PKCE支持）
func exchangeToken(tokenURL, code, redirectURI string) (*auth.OAuthTokens, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", "test-client-id")
	data.Set("client_secret", "test-secret")
	data.Set("code_verifier", codeVerifier) // 添加PKCE验证码

	req, _ := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var token auth.OAuthTokens
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, err
	}
	return &token, nil
}

// startCallbackServer 启动本地 HTTP 服务器，接收授权 code
func startCallbackServer() {
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		// 获取授权码 code
		code := r.URL.Query().Get("code")
		if code != "" {
			log.Println("Received code:", code)
			codeCh <- code // 将 code 发送到主线程
			fmt.Fprintf(w, "Authorization complete. You can close this window.")
		} else {
			http.Error(w, "Missing code", http.StatusBadRequest)
		}
	})

	// 启动 HTTP server 在 5173 端口监听回调
	log.Println("Starting server on http://localhost:5173")
	if err := http.ListenAndServe(":5173", nil); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
