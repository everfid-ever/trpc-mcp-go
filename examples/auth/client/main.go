package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	mcp "trpc.group/trpc-go/trpc-mcp-go"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
)

const (
	serverURL           = "http://localhost:3000" // MCP 资源服务器（origin）
	resourceMetadataURL = "http://localhost:3000/.well-known/oauth-protected-resource"
	redirectURL         = "http://localhost:5173/callback" // 本地回调
	scope               = "mcp.read mcp.write"
	callbackListenAddr  = ":5173"                      // 回调监听端口
	mcpEndpoint         = "http://localhost:3000/mcp/" // MCP 入口
)

func main() {
	log.Println("Starting OAuth client...")

	// 配置 AuthFlow
	authFlow := mcp.AuthFlowConfig{
		ServerURL: serverURL,
		ClientMetadata: auth.OAuthClientMetadata{
			ClientName:              strPtr("demo-client"),
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			TokenEndpointAuthMethod: "client_secret_post",
			RedirectURIs:            []string{redirectURL},
			Scope:                   strPtr(scope),
		},
		ResourceMetadataURL: strPtr(resourceMetadataURL),
		RedirectURL:         redirectURL,
		Scope:               strPtr(scope),
		OnRedirect: func(u *url.URL) error {
			log.Printf("Authorization required. Opening: %s", u.String())
			return nil
		},
	}

	// 创建 MCP 客户端
	client, err := mcp.NewClient(
		mcpEndpoint,
		mcp.Implementation{Name: "Auth-Example-Client", Version: "0.1.0"},
		mcp.WithAuthFlow(authFlow),
	)
	if err != nil {
		log.Fatalf("failed to create MCP client: %v", err)
	}

	// 启动本地回调：拿到 code -> 调用 CompleteAuthFlow
	authDone := make(chan struct{}, 1)
	cbServer := startCallbackServer(client, authDone)
	defer shutdownServer(cbServer)

	// 第一次尝试初始化预期会触发授权重定向
	log.Println("Initialize #1 (triggering authorization flow) ...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := client.Initialize(ctx, &mcp.InitializeRequest{}); err != nil {
		log.Printf("Initialize #1 returned (expected): %v", err)
	}

	// 等回调完成拿到 token
	select {
	case <-authDone:
		log.Println("Authorization completed via callback.")
	case <-time.After(3 * time.Minute):
		log.Fatal("timeout waiting for OAuth callback")
	}

	// 给一点时间让token完全生效
	time.Sleep(2 * time.Second)

	// 7) 再次初始化此时 TokenStore 已有 token，应成功
	log.Println("Initialize #2 (with valid tokens) ...")
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()

	initResp, err := client.Initialize(ctx2, &mcp.InitializeRequest{})
	if err != nil {
		log.Fatalf("Initialize #2 failed: %v", err)
	}
	log.Printf("MCP initialization successful. Server info: %+v", initResp.ServerInfo)
}

// 回调服务：/callback?code=...
func startCallbackServer(c *mcp.Client, done chan<- struct{}) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Callback received: %s", r.URL.RawQuery)

		code := r.URL.Query().Get("code")
		if code == "" {
			log.Printf("Missing code parameter")
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}

		state := r.URL.Query().Get("state")
		log.Printf("Received callback with code: %s, state: %s", code[:10]+"...", state[:10]+"...")

		// 用 SDK 提供的 CompleteAuthFlow 完成换 token
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		if err := c.CompleteAuthFlow(ctx, code); err != nil {
			log.Printf("Complete auth flow failed: %v", err)
			http.Error(w, fmt.Sprintf("complete auth failed: %v", err), http.StatusBadRequest)
			return
		}

		log.Println("Auth flow completed successfully")
		_, _ = w.Write([]byte("Authorization complete. You can close this tab."))

		// 通知主协程
		select {
		case done <- struct{}{}:
		default:
		}
	})

	srv := &http.Server{
		Addr:              callbackListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadTimeout:       10 * time.Second,
	}

	go func() {
		log.Printf("Callback server listening on %s", callbackListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("callback server error: %v", err)
		}
	}()
	return srv
}

func shutdownServer(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}
}

func strPtr(s string) *string {
	return &s
}
