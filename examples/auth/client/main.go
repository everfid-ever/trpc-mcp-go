package main

import (
	"context"
	"log"
	"net/url"
	"time"

	mcp "trpc.group/trpc-go/trpc-mcp-go"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/client"
)

func strPtr(s string) *string {
	return &s
}

func main() {
	log.Println("Starting OAuth client...")

	// 准备一个 OAuth ClientProvider
	provider := client.NewInMemoryOAuthClientProvider(
		"http://localhost:5173/callback",
		auth.OAuthClientMetadata{
			ClientName:    strPtr("demo-client"),
			RedirectURIs:  []string{"http://localhost:5173/callback"},
			ResponseTypes: []string{"code"},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
		},
		func(u *url.URL) error {
			// 这里打印授权URL，用户需要在浏览器中访问
			log.Println("Please open the following URL in your browser to authorize:")
			log.Println(u.String())
			log.Println("Once authorization is complete, the client will automatically continue...")
			return nil
		},
	)

	// 配置OAuth服务器URL
	serverUrl := "http://localhost:3000"

	// 创建 MCP 客户端，但先不初始化
	c, err := mcp.NewClient(
		serverUrl+"/mcp",
		mcp.Implementation{Name: "demo", Version: "0.1.0"},
		mcp.WithOAuthClientProvider(provider),
	)
	if err != nil {
		log.Fatal("Failed to create client: ", err)
	}

	ctx := context.Background()

	// 尝试进行OAuth授权
	log.Println("Starting OAuth authorization flow...")

	// 给用户一些时间完成浏览器授权
	// 在实际应用中，这里应该等待授权回调
	log.Println("Waiting for OAuth authorization to complete...")
	time.Sleep(5 * time.Second) // 给用户时间完成授权

	// 初始化MCP连接
	log.Println("Trying to initialize MCP connection...")
	if _, err := c.Initialize(ctx, nil); err != nil {
		log.Printf("Initialization failed: %v", err)
		log.Println("This may be because the OAuth authorization has not yet completed")
		log.Println("Please ensure that:")
		log.Println("1. Completed OAuth authorization in the browser")
		log.Println("2. The authorization server returns a valid access token")
		return
	}

	log.Println("MCP client initialization successful!")

	// 这里可以添加其他MCP调用
	// 例如：列出可用工具、调用工具等
}
