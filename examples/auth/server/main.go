package main

import (
	"context"
	"log"
	"net/url"
	"trpc.group/trpc-go/trpc-mcp-go/internal/errors"

	mcp "trpc.group/trpc-go/trpc-mcp-go"
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

	// 1. 创建代理 OAuth Provider，但指向本地端点
	provider := providers.NewProxyOAuthServerProvider(providers.ProxyOptions{
		Endpoints: providers.ProxyEndpoints{
			// 关键修改：将外部 URL 改为本地 URL
			AuthorizationURL: "http://localhost:3000/authorize",
			TokenURL:         "http://localhost:3000/token",
			RevocationURL:    "http://localhost:3000/revoke",
			RegistrationURL:  "http://localhost:3000/register",
		},
		VerifyAccessToken: func(token string) (*server.AuthInfo, error) {
			// 暂时返回一个模拟有效的用户信息
			return &server.AuthInfo{
				Token:    token,
				ClientID: "test-client-id",
				Scopes:   []string{"mcp.read", "mcp.write"},
			}, nil
		},
		GetClient: func(clientID string) (*auth.OAuthClientInformationFull, error) {
			// 返回一个模拟的客户端信息
			if clientID == "test-client-id" {
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
			}
			return nil, errors.NewOAuthError(errors.ErrInvalidClient, "Client not found", "")
		},
		Fetch: nil, // 可选自定义 HTTP 请求函数
	})

	ctx := context.Background()

	// 2. 构建访问令牌校验器（本地 JWKS）
	tv, err := server.NewTokenVerifier(ctx, server.TokenVerifierConfig{
		Local: &server.LocalJWKSConfig{
			JWKS: `{
                "keys": [
                    {
                        "kty": "oct",
                        "k": "dGVzdC1zZWNyZXQta2V5LWZvci1qd3QtdG9rZW4tc2lnbmluZw==",
                        "kid": "test-key-id",
                        "alg": "HS256"
                    }
                ]
            }`,
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	//// 3. 手动生成 OAuth 元数据，用于 .well-known 端点
	//meta, err := router.CreateOAuthMetadata(struct {
	//	Provider                server.OAuthServerProvider
	//	IssuerUrl               *url.URL
	//	BaseUrl                 *url.URL
	//	ServiceDocumentationUrl *url.URL
	//	ScopesSupported         []string
	//}{
	//	Provider:                provider,
	//	IssuerUrl:               mustURL("http://localhost:3000"),
	//	BaseUrl:                 mustURL("http://localhost:3000"),
	//	ServiceDocumentationUrl: mustURL("http://localhost:3000/docs"),
	//	ScopesSupported:         []string{"mcp.read", "mcp.write"},
	//})
	//if err != nil {
	//	log.Fatal(err)
	//}

	// 4. 启动 MCP Server（包含鉴权上下文与 .well-known 元数据）
	mcpServer := mcp.NewServer(
		"Auth-Example-Server",
		"1.0.0",
		mcp.WithServerAddress(":3000"),
		mcp.WithServerPath("/mcp"),

		// 在每个请求前执行：抽取 Authorization: Bearer 并校验
		mcp.WithHTTPContextFunc(mcp.NewAuthHTTPContextFunc(*tv, mcp.ServerAuthConfig{
			Issuer:         "http://localhost:3000",
			Audience:       []string{"http://localhost:3000"},
			RequiredScopes: []string{"mcp.read"},
		})),

		//// 安装 .well-known 元数据端点
		//mcp.WithOAuthMetadata(router.AuthMetadataOptions{
		//	OAuthMetadata:           meta,
		//	ResourceServerUrl:       mustURL("http://localhost:3000"),
		//	ServiceDocumentationUrl: mustURL("http://localhost:3000/docs"),
		//	ScopesSupported:         []string{"mcp.read", "mcp.write"},
		//}),

		// OAuth 路由：暴露 /authorize、/token 等端点
		mcp.WithOAuthRoutes(router.AuthRouterOptions{
			Provider:        provider,
			IssuerUrl:       mustURL("http://localhost:3000"),
			BaseUrl:         mustURL("http://localhost:3000"),
			ScopesSupported: []string{"mcp.read", "mcp.write"},
		}),
	)

	log.Println("Server listening on :3000")
	log.Println("OAuth endpoints available:")
	log.Println("  - Authorization: http://localhost:3000/authorize")
	log.Println("  - Token: http://localhost:3000/token")
	log.Println("  - Metadata: http://localhost:3000/.well-known/oauth-authorization-server")

	if err := mcpServer.Start(); err != nil {
		log.Fatal(err)
	}
}
