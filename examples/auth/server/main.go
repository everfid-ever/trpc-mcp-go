package main

import (
	"log"
	"net/url"
	"trpc.group/trpc-go/trpc-mcp-go"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
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

func strPtr(s string) *string {
	return &s
}

func main() {
	log.Println("Starting server...")

	// 1. 创建 OAuth Provider
	provider := providers.NewProxyOAuthServerProvider(providers.ProxyOptions{
		Endpoints: providers.ProxyEndpoints{
			AuthorizationURL: "https://auth.example.com/authorize",
			TokenURL:         "https://auth.example.com/token",
			RevocationURL:    "https://auth.example.com/revoke",
			RegistrationURL:  "https://auth.example.com/register",
		},
		VerifyAccessToken: func(token string) (*server.AuthInfo, error) {
			// 暂时返回一个模拟有效的用户信息
			return &server.AuthInfo{
				Token:    token,
				ClientID: "test-client-id",
				Scopes:   []string{"mcp.read", "mcp.write"},
				// ExpiresAt, Resource, Extra 都是可选的
			}, nil
		},
		GetClient: func(clientID string) (*auth.OAuthClientInformationFull, error) {
			// 返回一个模拟的客户端信息
			return &auth.OAuthClientInformationFull{
				OAuthClientMetadata: auth.OAuthClientMetadata{
					RedirectURIs:  []string{"http://localhost:5173/callback"},
					ResponseTypes: []string{"code"},
					GrantTypes:    []string{"authorization_code", "refresh_token"},
					ClientName:    strPtr("demo-client"),
				},
				OAuthClientInformation: auth.OAuthClientInformation{
					ClientID:     clientID,
					ClientSecret: "test-secret", // 实际应用中应该是安全的密钥
				},
			}, nil
		},
		Fetch: nil, // 可选自定义 HTTP 请求函数
	})

	//ctx := context.Background()
	//
	//// 2. 构建访问令牌校验器（远程 JWKS）
	//tv, err := server.NewTokenVerifier(ctx, server.TokenVerifierConfig{
	//	Remote: &server.RemoteJWKSConfig{
	//		URLs:            []string{"https://issuer.example.com/.well-known/jwks.json"},
	//		RefreshInterval: 30 * time.Minute,
	//		IssuerToURL: map[string]string{
	//			"https://issuer.example.com": "https://issuer.example.com/.well-known/jwks.json",
	//		},
	//	},
	//})
	//if err != nil {
	//	log.Fatal(err)
	//}

	//// 3. 手动生成 OAuth 元数据，用于 .well-known 端点
	//meta, err := router.CreateOAuthMetadata(struct {
	//	Provider                server.OAuthServerProvider
	//	IssuerUrl               *url.URL
	//	BaseUrl                 *url.URL
	//	ServiceDocumentationUrl *url.URL
	//	ScopesSupported         []string
	//}{
	//	Provider:                provider,
	//	IssuerUrl:               mustURL("https://issuer.example.com"),
	//	BaseUrl:                 mustURL("https://api.example.com"),
	//	ServiceDocumentationUrl: mustURL("https://docs.example.com/mcp"),
	//	ScopesSupported:         []string{"mcp.read", "mcp.write"},
	//})
	//if err != nil {
	//	log.Fatal(err)
	//}

	// 4. 启动 MCP Server（含鉴权上下文与 .well-known 元数据）
	mcpServer := mcp.NewServer(
		"Auth-Example-Server",
		"1.0.0",
		mcp.WithServerAddress(":3000"),
		mcp.WithServerPath("/mcp"),

		//// 在每个请求前执行：抽取 Authorization: Bearer 并校验
		//mcp.WithHTTPContextFunc(mcp.NewAuthHTTPContextFunc(*tv, mcp.ServerAuthConfig{
		//	Issuer:         "https://issuer.example.com",
		//	Audience:       []string{"https://api.example.com"},
		//	RequiredScopes: []string{"mcp.read"},
		//})),

		//// 安装 .well-known 元数据端点
		//mcp.WithOAuthMetadata(router.AuthMetadataOptions{
		//	OAuthMetadata:           meta,
		//	ResourceServerUrl:       mustURL("https://api.example.com"),
		//	ServiceDocumentationUrl: mustURL("https://docs.example.com/mcp"),
		//	ScopesSupported:         []string{"mcp.read", "mcp.write"},
		//}),

		// OAuth 路由：暴露 /authorize、/token 等端点
		mcp.WithOAuthRoutes(router.AuthRouterOptions{
			Provider:        provider,
			IssuerUrl:       mustURL("https://issuer.example.com"),
			BaseUrl:         mustURL("https://api.example.com"),
			ScopesSupported: []string{"mcp.read", "mcp.write"},
		}),
	)

	log.Println("Server listening on :3000")
	if err := mcpServer.Start(); err != nil {
		log.Fatal(err)
	}
}
