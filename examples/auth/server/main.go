package main

import (
	"context"
	"log"
	"net/url"
	"time"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"

	mcp "trpc.group/trpc-go/trpc-mcp-go"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/providers"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/router"
)

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func main() {
	// 创建 OAuth Provider
	provider := providers.NewProxyOAuthServerProvider(providers.ProxyOptions{
		Endpoints: providers.ProxyEndpoints{
			AuthorizationURL: "https://auth.example.com/authorize",
			TokenURL:         "https://auth.example.com/token",
			RevocationURL:    "https://auth.example.com/revoke",
			RegistrationURL:  "https://auth.example.com/register",
		},
		VerifyAccessToken: func(token string) (*server.AuthInfo, error) {
			// 在这里验证 token
			// 例如调用一个远程服务验证 JWT token，或查数据库等
			return nil, nil
		},
		GetClient: func(clientID string) (*auth.OAuthClientInformationFull, error) {
			// 获取客户端信息，例如从数据库查询
			return nil, nil
		},
		Fetch: nil, // 可选自定义 HTTP 请求函数
	})

	ctx := context.Background()

	// 1) 构建访问令牌校验器（远程 JWKS）
	tv, err := server.NewTokenVerifier(ctx, server.TokenVerifierConfig{
		Remote: &server.RemoteJWKSConfig{
			URLs:            []string{"https://issuer.example.com/.well-known/jwks.json"},
			RefreshInterval: 30 * time.Minute,
			IssuerToURL: map[string]string{
				"https://issuer.example.com": "https://issuer.example.com/.well-known/jwks.json",
			},
		},
		// 如需本地 JWKS：Local: &server.LocalJWKSConfig{File: "jwks.json"},
	})
	if err != nil {
		log.Fatal(err)
	}

	// 2) （可选）手动生成 OAuth 元数据，用于 .well-known 端点
	meta, err := router.CreateOAuthMetadata(struct {
		Provider                server.OAuthServerProvider
		IssuerUrl               *url.URL
		BaseUrl                 *url.URL
		ServiceDocumentationUrl *url.URL
		ScopesSupported         []string
	}{
		Provider:                nil, // 仅挂元数据可为 nil；需要 /authorize、/token 时请提供 Provider 并改用 WithOAuthRoutes
		IssuerUrl:               mustURL("https://issuer.example.com"),
		BaseUrl:                 mustURL("https://api.example.com"),
		ServiceDocumentationUrl: mustURL("https://docs.example.com/mcp"),
		ScopesSupported:         []string{"mcp.read", "mcp.write"},
	})
	if err != nil {
		log.Fatal(err)
	}

	// 3) 组装并启动 MCP Server（含鉴权上下文与 .well-known 元数据）
	server := mcp.NewServer(
		"mcp-auth-demo",
		"1.0.0",
		mcp.WithServerAddress(":3000"),
		mcp.WithServerPath("/mcp"),

		// 在每个请求前执行：抽取 Authorization: Bearer 并校验
		mcp.WithHTTPContextFunc(mcp.NewAuthHTTPContextFunc(*tv, mcp.ServerAuthConfig{
			Issuer:         "https://issuer.example.com",
			Audience:       []string{"https://api.example.com"},
			RequiredScopes: []string{"mcp.read"},
		})),

		// 仅安装 .well-known 元数据端点（不依赖 Provider）
		mcp.WithOAuthMetadata(router.AuthMetadataOptions{
			OAuthMetadata:           meta,
			ResourceServerUrl:       mustURL("https://api.example.com"),
			ServiceDocumentationUrl: mustURL("https://docs.example.com/mcp"),
			ScopesSupported:         []string{"mcp.read", "mcp.write"},
		}),

		// OAuth 路由：暴露 /authorize、/token 等端点
		mcp.WithOAuthRoutes(router.AuthRouterOptions{
			Provider:        provider,
			IssuerUrl:       mustURL("https://issuer.example.com"),
			BaseUrl:         mustURL("https://api.example.com"),
			ScopesSupported: []string{"mcp.read", "mcp.write"},
		}),
	)

	log.Println("Server listening on :3000")
	if err := server.Start(); err != nil {
		log.Fatal(err)
	}
}
