package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/router"
)

type DemoProvider struct {
	clients        *server.OAuthClientsStore
	mu             sync.Mutex
	codeChallenges map[string]string // authCode -> code_challenge
}

func NewDemoProvider(store *server.OAuthClientsStore) *DemoProvider {
	return &DemoProvider{
		clients:        store,
		codeChallenges: make(map[string]string),
	}
}

func (d *DemoProvider) ClientsStore() *server.OAuthClientsStore { return d.clients }

// /authorize：发授权码，并把该 code 的 challenge 存起来
func (d *DemoProvider) Authorize(client auth.OAuthClientInformationFull, params server.AuthorizationParams, w http.ResponseWriter, r *http.Request) error {
	code := "demo-code" // 演示写死；真实环境生成随机一次性 code

	if params.CodeChallenge != "" {
		d.mu.Lock()
		d.codeChallenges[code] = params.CodeChallenge
		d.mu.Unlock()
		fmt.Println("[DEBUG] save challenge for code:", code, "challenge:", params.CodeChallenge)
	}

	q := url.Values{}
	q.Set("code", code)
	if params.State != "" {
		q.Set("state", params.State)
	}
	http.Redirect(w, r, params.RedirectURI+"?"+q.Encode(), http.StatusFound)
	return nil
}

// /token 本地 PKCE 校验前会调用它取出 challenge；取不到就会报你看到的错误
func (d *DemoProvider) ChallengeForAuthorizationCode(client auth.OAuthClientInformationFull, code string) (string, error) {
	d.mu.Lock()
	ch := d.codeChallenges[code]
	d.mu.Unlock()
	if ch == "" {
		return "", fmt.Errorf("unknown authorization code")
	}
	fmt.Println("[DEBUG] load challenge for code:", code, "challenge:", ch)
	return ch, nil
}

func (d *DemoProvider) ExchangeAuthorizationCode(client auth.OAuthClientInformationFull, code string, codeVerifier *string, redirectUri *string, resource *url.URL) (*auth.OAuthTokens, error) {
	// 走到这里说明本地 PKCE 校验已经通过（由 TokenHandler 完成）
	tokenType := "Bearer"
	expiresIn := int64(3600)
	scope := "read write"
	refresh := "demo-refresh"

	// 可选：用完 code 就清理，防复用
	d.mu.Lock()
	delete(d.codeChallenges, code)
	d.mu.Unlock()

	return &auth.OAuthTokens{
		AccessToken:  "demo-access-token",
		TokenType:    tokenType,
		ExpiresIn:    &expiresIn,
		Scope:        &scope,
		RefreshToken: &refresh,
	}, nil
}

func (d *DemoProvider) ExchangeRefreshToken(client auth.OAuthClientInformationFull, refreshToken string, scopes []string, resource *url.URL) (*auth.OAuthTokens, error) {
	tokenType := "Bearer"
	expiresIn := int64(3600)
	scope := "read"
	return &auth.OAuthTokens{
		AccessToken: "refreshed-access-token",
		TokenType:   tokenType,
		ExpiresIn:   &expiresIn,
		Scope:       &scope,
	}, nil
}

func (d *DemoProvider) VerifyAccessToken(token string) (*server.AuthInfo, error) {
	return &server.AuthInfo{
		Token:    token,
		ClientID: "demo-client",
		Scopes:   []string{"read", "write"},
	}, nil
}

func (d *DemoProvider) RevokeToken(client auth.OAuthClientInformationFull, req auth.OAuthTokenRevocationRequest) error {
	fmt.Println("Revoked token:", req.Token)
	return nil
}

func main() {
	// 注册一个 demo client
	client := &auth.OAuthClientInformationFull{
		OAuthClientMetadata: auth.OAuthClientMetadata{
			RedirectURIs: []string{"http://localhost:8080/callback"},
			Scope:        strPtr("read write"),
		},
		OAuthClientInformation: auth.OAuthClientInformation{
			ClientID:     "demo-client",
			ClientSecret: "demo-secret",
		},
	}

	store := server.NewOAuthClientStore(func(id string) (*auth.OAuthClientInformationFull, error) {
		if id == client.ClientID {
			return client, nil
		}
		return nil, nil
	})

	// 整个进程只创建这一个 provider 实例，供 /authorize 与 /token 共用
	provider := NewDemoProvider(store)

	mux := http.NewServeMux()
	issuerURL, _ := url.Parse("http://localhost:8080")

	// 由路由器挂载 /authorize 与 /token（含方法校验与参数校验，中间件里会做）
	if err := router.McpAuthRouter(mux, router.AuthRouterOptions{
		Provider:        provider,
		IssuerUrl:       issuerURL,
		BaseUrl:         issuerURL,
		ScopesSupported: []string{"read", "write"},
	}); err != nil {
		log.Fatalf("setup auth router failed: %v", err)
	}

	// 受保护资源示例
	mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("missing bearer token"))
			return
		}
		token := strings.TrimPrefix(authz, "Bearer ")
		info, err := provider.VerifyAccessToken(token)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("invalid token"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"clientId": info.ClientID,
			"scopes":   info.Scopes,
			"data":     "Here is your protected data",
		})
	})

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Println("OAuth2.1 demo server with local PKCE verification on http://localhost:8080")
	log.Fatal(srv.ListenAndServe())
}

func strPtr(s string) *string {
	return &s
}
