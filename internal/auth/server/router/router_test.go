package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	srv "trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
)

// ====== stub providers ======

type fullProvider struct{}

func (p *fullProvider) ClientsStore() *srv.OAuthClientsStore {
	// 非 nil 以启用 supportsClientRegistration()
	return new(srv.OAuthClientsStore)
}

func (p *fullProvider) Authorize(client auth.OAuthClientInformationFull, params srv.AuthorizationParams, w http.ResponseWriter, r *http.Request) error {
	// 按规范 302 回跳并带 code/state
	u, _ := url.Parse(params.RedirectURI)
	q := u.Query()
	q.Set("code", "mock_auth_code")
	if params.State != "" {
		q.Set("state", params.State)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
	return nil
}

func (p *fullProvider) ChallengeForAuthorizationCode(client auth.OAuthClientInformationFull, code string) (string, error) {
	return "mock_challenge", nil
}

func (p *fullProvider) ExchangeAuthorizationCode(client auth.OAuthClientInformationFull, code string, verifier *string, redirect *string, resource *url.URL) (*auth.OAuthTokens, error) {
	expires := int64(3600)
	rt := "mock_refresh_token"
	return &auth.OAuthTokens{
		AccessToken:  "mock_access_token",
		TokenType:    "bearer",
		ExpiresIn:    &expires,
		RefreshToken: &rt,
	}, nil
}

func (p *fullProvider) ExchangeRefreshToken(client auth.OAuthClientInformationFull, rt string, scopes []string, resource *url.URL) (*auth.OAuthTokens, error) {
	expires := int64(3600)
	newRT := "new_mock_refresh_token"
	return &auth.OAuthTokens{
		AccessToken:  "new_mock_access_token",
		TokenType:    "bearer",
		ExpiresIn:    &expires,
		RefreshToken: &newRT,
	}, nil
}

func (p *fullProvider) VerifyAccessToken(token string) (*srv.AuthInfo, error) {
	if token == "valid_token" {
		exp := time.Now().Add(time.Hour).Unix()
		return &srv.AuthInfo{
			Token:     token,
			ClientID:  "valid-client",
			Scopes:    []string{"read", "write"},
			ExpiresAt: &exp,
		}, nil
	}
	return nil, ErrInvalid // 用测试内的简化错误
}

// 声明支持撤销：用于让 /revoke 路由被挂载
func (p *fullProvider) RevokeToken(client auth.OAuthClientInformationFull, req auth.OAuthTokenRevocationRequest) error {
	return nil
}

// 通过空方法实现标记接口 server.SupportTokenRevocation
var _ srv.SupportTokenRevocation = (*fullProvider)(nil)

// 通过空方法实现标记接口 server.SupportDynamicClientRegistration（路由里用 type assertion 判断）
type dynReg interface{ SupportDynamicClientRegistration() }

func (p *fullProvider) SupportDynamicClientRegistration() {}

// ---- minimal provider（不支持注册与撤销） ----

type minimalProvider struct{}

func (p *minimalProvider) ClientsStore() *srv.OAuthClientsStore { return nil }
func (p *minimalProvider) Authorize(client auth.OAuthClientInformationFull, params srv.AuthorizationParams, w http.ResponseWriter, r *http.Request) error {
	u, _ := url.Parse(params.RedirectURI)
	q := u.Query()
	q.Set("code", "mock_auth_code")
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
	return nil
}
func (p *minimalProvider) ChallengeForAuthorizationCode(client auth.OAuthClientInformationFull, code string) (string, error) {
	return "mock_challenge", nil
}
func (p *minimalProvider) ExchangeAuthorizationCode(client auth.OAuthClientInformationFull, code string, verifier *string, redirect *string, resource *url.URL) (*auth.OAuthTokens, error) {
	expires := int64(3600)
	return &auth.OAuthTokens{AccessToken: "mock_access_token", TokenType: "bearer", ExpiresIn: &expires}, nil
}
func (p *minimalProvider) ExchangeRefreshToken(client auth.OAuthClientInformationFull, rt string, scopes []string, resource *url.URL) (*auth.OAuthTokens, error) {
	expires := int64(3600)
	return &auth.OAuthTokens{AccessToken: "new_mock_access_token", TokenType: "bearer", ExpiresIn: &expires}, nil
}
func (p *minimalProvider) VerifyAccessToken(token string) (*srv.AuthInfo, error) {
	exp := time.Now().Add(time.Hour).Unix()
	return &srv.AuthInfo{Token: token, ClientID: "valid-client", Scopes: []string{"read"}, ExpiresAt: &exp}, nil
}

// ====== tests ======

func Test_McpAuthRouter_RouterCreation_Validation(t *testing.T) {
	mux := http.NewServeMux()
	issuerHTTP, _ := url.Parse("http://auth.example.com") // 非 https
	err := McpAuthRouter(mux, AuthRouterOptions{
		Provider:  &fullProvider{},
		IssuerUrl: issuerHTTP,
	})
	if err == nil {
		t.Fatalf("expected error for non-HTTPS issuer")
	}

	muxOK := http.NewServeMux()
	issuerHTTPS, _ := url.Parse("https://auth.example.com")
	if err := McpAuthRouter(muxOK, AuthRouterOptions{
		Provider:  &fullProvider{},
		IssuerUrl: issuerHTTPS,
	}); err != nil {
		t.Fatalf("unexpected error for valid https issuer: %v", err)
	}
}

func Test_Metadata_AuthorizationServer_Full(t *testing.T) {
	mux := http.NewServeMux()

	issuer, _ := url.Parse("https://auth.example.com")
	if err := McpAuthRouter(mux, AuthRouterOptions{
		Provider:                &fullProvider{},
		IssuerUrl:               issuer,
		ServiceDocumentationUrl: mustParseURL("https://docs.example.com"),
		ScopesSupported:         []string{"read", "write"},
	}); err != nil {
		t.Fatalf("router init failed: %v", err)
	}

	ts := httptest.NewServer(mux)
	defer ts.Close()

	res, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("GET metadata failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)

	// 必填
	expectStr(t, body, "issuer", "https://auth.example.com/")
	expectStr(t, body, "authorization_endpoint", "https://auth.example.com/authorize")
	expectStr(t, body, "token_endpoint", "https://auth.example.com/token")

	// 能力/推荐字段（由 CreateOAuthMetadata 生成）
	expectArr(t, body, "response_types_supported", []string{"code"})
	expectArr(t, body, "grant_types_supported", []string{"authorization_code", "refresh_token"})
	expectArr(t, body, "code_challenge_methods_supported", []string{"S256"})
	// token 端点认证方法
	expectArr(t, body, "token_endpoint_auth_methods_supported", containsAny("client_secret_post", "client_secret_basic"))

	// 因 provider 支持撤销/注册，应出现对应端点
	expectStr(t, body, "revocation_endpoint", "https://auth.example.com/revoke")
	expectStr(t, body, "registration_endpoint", "https://auth.example.com/register")

	// 可选
	expectStr(t, body, "service_documentation", "https://docs.example.com/")
}

func Test_Metadata_ProtectedResource_Full(t *testing.T) {
	mux := http.NewServeMux()

	issuer, _ := url.Parse("https://auth.example.com")
	if err := McpAuthRouter(mux, AuthRouterOptions{
		Provider:                &fullProvider{},
		IssuerUrl:               issuer,
		ServiceDocumentationUrl: mustParseURL("https://docs.example.com"),
		ScopesSupported:         []string{"read", "write"},
		ResourceName:            strPtr("Test API"),
	}); err != nil {
		t.Fatalf("router init failed: %v", err)
	}

	ts := httptest.NewServer(mux)
	defer ts.Close()

	res, err := http.Get(ts.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("GET resource metadata failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)

	expectStr(t, body, "resource", "https://auth.example.com/") // McpAuthRouter 中用 issuer 作为 resourceBase
	expectArr(t, body, "authorization_servers", []string{"https://auth.example.com/"})
	expectArr(t, body, "scopes_supported", []string{"read", "write"})
	expectStr(t, body, "resource_name", "Test API")
	expectStr(t, body, "resource_documentation", "https://docs.example.com/")
}

func Test_Metadata_Minimal_NoOptionalFields(t *testing.T) {
	mux := http.NewServeMux()

	issuer, _ := url.Parse("https://auth.example.com")
	if err := McpAuthRouter(mux, AuthRouterOptions{
		Provider:  &minimalProvider{},
		IssuerUrl: issuer,
	}); err != nil {
		t.Fatalf("router init failed: %v", err)
	}

	ts := httptest.NewServer(mux)
	defer ts.Close()

	// 授权服务器元数据：可选字段省略
	as, _ := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	defer as.Body.Close()
	var a map[string]any
	_ = json.NewDecoder(as.Body).Decode(&a)
	if _, ok := a["service_documentation"]; ok {
		t.Fatalf("service_documentation should be omitted")
	}
	if _, ok := a["scopes_supported"]; ok {
		t.Fatalf("scopes_supported should be omitted")
	}

	// 受保护资源元数据：可选字段省略
	pr, _ := http.Get(ts.URL + "/.well-known/oauth-protected-resource")
	defer pr.Body.Close()
	var p map[string]any
	_ = json.NewDecoder(pr.Body).Decode(&p)
	if _, ok := p["scopes_supported"]; ok {
		t.Fatalf("scopes_supported should be omitted")
	}
	if _, ok := p["resource_name"]; ok {
		t.Fatalf("resource_name should be omitted")
	}
	if _, ok := p["resource_documentation"]; ok {
		t.Fatalf("resource_documentation should be omitted")
	}
}

func Test_Routes_Register_And_Revoke_Presence(t *testing.T) {
	mux := http.NewServeMux()

	issuer, _ := url.Parse("https://auth.example.com")
	if err := McpAuthRouter(mux, AuthRouterOptions{
		Provider:  &fullProvider{},
		IssuerUrl: issuer,
	}); err != nil {
		t.Fatalf("router init failed: %v", err)
	}
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// /register 存在（不断言 200，只要不是 404，说明路由已挂）
	r1, _ := http.PostForm(ts.URL+"/register", url.Values{
		"redirect_uris": {"https://example.com/callback"},
	})
	if r1.StatusCode == http.StatusNotFound {
		t.Fatalf("/register should be registered (got 404)")
	}

	// /revoke 存在
	r2, _ := http.PostForm(ts.URL+"/revoke", url.Values{
		"client_id":     {"valid-client"},
		"client_secret": {"valid-secret"},
		"token":         {"token_to_revoke"},
	})
	if r2.StatusCode == http.StatusNotFound {
		t.Fatalf("/revoke should be registered (got 404)")
	}
}

func Test_Routes_Excluded_When_MinimalProvider(t *testing.T) {
	mux := http.NewServeMux()
	issuer, _ := url.Parse("https://auth.example.com")
	if err := McpAuthRouter(mux, AuthRouterOptions{
		Provider:  &minimalProvider{},
		IssuerUrl: issuer,
	}); err != nil {
		t.Fatalf("router init failed: %v", err)
	}
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// /register 不存在
	r1, _ := http.PostForm(ts.URL+"/register", url.Values{
		"redirect_uris": {"https://example.com/callback"},
	})
	if r1.StatusCode != http.StatusNotFound {
		t.Fatalf("/register should be 404 for minimal provider, got %d", r1.StatusCode)
	}

	// /revoke 不存在
	r2, _ := http.PostForm(ts.URL+"/revoke", url.Values{
		"client_id":     {"valid-client"},
		"client_secret": {"valid-secret"},
		"token":         {"token_to_revoke"},
	})
	if r2.StatusCode != http.StatusNotFound {
		t.Fatalf("/revoke should be 404 for minimal provider, got %d", r2.StatusCode)
	}
}

// ====== helpers ======

var ErrInvalid = &struct{ error }{}

func mustParseURL(s string) *url.URL { u, _ := url.Parse(s); return u }
func strPtr(s string) *string        { return &s }

func expectStr(t *testing.T, m map[string]any, key, want string) {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("missing key %q", key)
	}
	vs, _ := v.(string)
	if vs != want {
		t.Fatalf("%s mismatch: got %q want %q", key, vs, want)
	}
}

func expectArr(t *testing.T, m map[string]any, key string, want []string) {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("missing key %q", key)
	}
	arr, ok := v.([]any)
	if !ok {
		t.Fatalf("%s is not array", key)
	}
	got := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			got = append(got, s)
		}
	}
	if len(want) == 1 && strings.HasPrefix(want[0], "__any__:") {
		// containsAny 模式
		needle := strings.TrimPrefix(want[0], "__any__:")
		found := false
		for _, g := range got {
			if g == needle {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s expected to contain %q, got %v", key, needle, got)
		}
		return
	}
	if len(got) != len(want) {
		t.Fatalf("%s length mismatch: got %v want %v", key, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s[%d] mismatch: got %q want %q", key, i, got[i], want[i])
		}
	}
}

func containsAny(values ...string) []string {
	// 小技巧：用 expectArr 的 "__any__" 模式，只需包含其一即可及格
	if len(values) == 0 {
		return nil
	}
	return []string{"__any__:" + values[0]}
}
