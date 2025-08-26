package main

import (
	"fmt"
	"net/http"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/providers"
)

// mock 实现：校验 token 并返回 AuthInfo
func verifyAccessToken(token string) (*server.AuthInfo, error) {
	if token == "valid-token" {
		return &server.AuthInfo{
			Subject: "user123",
			Scopes:  []string{"read", "write"},
		}, nil
	}
	return nil, fmt.Errorf("invalid token")
}

// mock 实现：获取客户端信息
func getClient(clientID string) (*auth.OAuthClientInformationFull, error) {
	return &auth.OAuthClientInformationFull{
		ClientID:     clientID,
		ClientSecret: "secret",
	}, nil
}

func main() {
	// 配置 OAuth Provider
	provider := providers.NewProxyOAuthServerProvider(providers.ProxyOptions{
		Endpoints: providers.ProxyEndpoints{
			AuthorizationURL: "https://auth.example.com/authorize",
			TokenURL:         "https://auth.example.com/token",
			RevocationURL:    "https://auth.example.com/revoke",
			RegistrationURL:  "https://auth.example.com/register",
		},
		VerifyAccessToken: verifyAccessToken,
		GetClient:         getClient,
	})

	// 用 provider 来保护一个 API
	http.HandleFunc("/secure", func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}
		authInfo, err := provider.VerifyAccessToken(token[len("Bearer "):])
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, "Hello, %s! Scopes: %v\n", authInfo.Subject, authInfo.Scopes)
	})

	fmt.Println("Auth demo server running on :8080")
	http.ListenAndServe(":8080", nil)
}
