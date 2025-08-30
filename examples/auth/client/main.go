package main

import (
	"context"
	"log"
	"net/url"

	mcp "trpc.group/trpc-go/trpc-mcp-go"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/client"
)

func strPtr(s string) *string {
	return &s
}

func main() {
	// 准备一个 OAuth ClientProvider
	provider := client.NewInMemoryOAuthClientProvider(
		"http://localhost:5173/callback",
		auth.OAuthClientMetadata{
			ClientName:    strPtr("demo-client"),
			RedirectURIs:  []string{"http://localhost:5173/callback"},
			ResponseTypes: []string{"code"},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			// 其他可选元数据字段按需填充……
		},
		func(u *url.URL) error {
			// 这里可以打开浏览器，或打印地址让用户点击
			log.Println("Open browser to authorize:", u.String())
			return nil
		},
	)

	// 2) 创建 MCP 客户端并注入 OAuth（Option 化）
	c, err := mcp.NewClient(
		"https://api.example.com/mcp",
		mcp.Implementation{Name: "demo", Version: "0.1.0"},
		mcp.WithOAuthClientProvider(provider), // 正确的选项名
	)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	// 3) Initialize 第二个参数：可传 nil 或 &mcp.InitializeRequest{}
	if _, err := c.Initialize(ctx, nil); err != nil {
		log.Fatal("Initialize failed:", err)
	}

	// ... 后续调用
}
