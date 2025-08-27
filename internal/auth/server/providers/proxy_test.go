package providers

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	oauthErrors "trpc.group/trpc-go/trpc-mcp-go/internal/errors"
)

// 共享变量
var (
	validClient = auth.OAuthClientInformationFull{
		OAuthClientInformation: auth.OAuthClientInformation{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		},
		OAuthClientMetadata: auth.OAuthClientMetadata{
			RedirectURIs: []string{"https://example.com/callback"},
		},
	}

	baseOptions = ProxyOptions{
		Endpoints: ProxyEndpoints{
			AuthorizationURL: "https://auth.example.com/authorize",
			TokenURL:         "https://auth.example.com/token",
			RevocationURL:    "https://auth.example.com/revoke",
			RegistrationURL:  "https://auth.example.com/register",
		},
		VerifyAccessToken: nil, // 在 TestMain 中设置
		GetClient:         nil, // 在 TestMain 中设置
		Fetch:             nil, // 在测试中设置 mockFetch
	}

	RefreshToken      = "new-refresh-token"
	ExpiresIn         = int64(3600)
	mockTokenResponse = auth.OAuthTokens{
		AccessToken:  "new-access-token",
		TokenType:    "Bearer",
		ExpiresIn:    &ExpiresIn,
		RefreshToken: &RefreshToken,
	}

	// 模拟 fetch 的函数，匹配 auth.FetchFunc
	mockFetch func(url string, req *http.Request) (*http.Response, error)
)

// TestMain 初始化
func TestMain(m *testing.M) {
	// 设置 mock 函数
	baseOptions.VerifyAccessToken = func(token string) (*server.AuthInfo, error) {
		if token == "valid-token" {
			ExpiresAt := time.Now().Unix() + 3600
			return &server.AuthInfo{
				Token:     token,
				ClientID:  "test-client",
				Scopes:    []string{"read", "write"},
				ExpiresAt: &ExpiresAt,
			}, nil
		}
		return nil, oauthErrors.NewOAuthError(oauthErrors.ErrInvalidToken, "Invalid token", "")
	}

	baseOptions.GetClient = func(clientID string) (*auth.OAuthClientInformationFull, error) {
		if clientID == "test-client" {
			return &validClient, nil
		}
		return nil, nil
	}

	// 运行测试
	code := m.Run()

	// 清理
	mockFetch = nil
	os.Exit(code)
}

// 测试代码
func TestProxyOAuthServerProvider(t *testing.T) {
	provider := NewProxyOAuthServerProvider(baseOptions)

	// 模拟 codeVerifier 和 redirectURI
	codeVerifier := "test-verifier"
	redirectURI := "https://example.com/callback"

	t.Run("Authorization", func(t *testing.T) {
		t.Run("Redirects to authorization endpoint with correct parameters", func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/", nil)
			resource, _ := url.Parse("https://api.example.com/resource")
			err := provider.Authorize(validClient, server.AuthorizationParams{
				RedirectURI:   "https://example.com/callback",
				CodeChallenge: "test-challenge",
				State:         "test-state",
				Scopes:        []string{"read", "write"},
				Resource:      resource,
			}, rr, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// 验证状态码和 Location 头部
			if rr.Code != http.StatusFound {
				t.Errorf("expected status code %d, got %d", http.StatusFound, rr.Code)
			}

			gotURL := rr.Header().Get("Location")
			t.Logf("got redirect URL: %s", gotURL) // 调试输出
			expectedURL, _ := url.Parse("https://auth.example.com/authorize")
			q := expectedURL.Query()
			q.Set("client_id", "test-client")
			q.Set("response_type", "code")
			q.Set("redirect_uri", "https://example.com/callback")
			q.Set("code_challenge", "test-challenge")
			q.Set("code_challenge_method", "S256")
			q.Set("state", "test-state")
			q.Set("scope", "read write")
			q.Set("resource", "https://api.example.com/resource")
			expectedURL.RawQuery = q.Encode()

			if gotURL != expectedURL.String() {
				t.Errorf("expected redirect URL %s, got %s", expectedURL.String(), gotURL)
			}
		})
	})

	t.Run("Token Exchange", func(t *testing.T) {
		t.Run("Exchanges authorization code for tokens", func(t *testing.T) {
			mockFetch = func(url string, req *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(req.Body)
				t.Logf("request body: %s", string(body)) // 调试请求体
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"access_token":"new-access-token","token_type":"Bearer","expires_in":3600,"refresh_token":"new-refresh-token"}`)),
				}, nil
			}
			provider.fetch = mockFetch

			tokens, err := provider.ExchangeAuthorizationCode(validClient, "test-code", &codeVerifier, nil, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			t.Logf("tokens: %+v", tokens) // 调试输出
			if tokens.AccessToken != mockTokenResponse.AccessToken {
				t.Errorf("expected access_token %s, got %s", mockTokenResponse.AccessToken, tokens.AccessToken)
			}
			if tokens.TokenType != mockTokenResponse.TokenType {
				t.Errorf("expected token_type %s, got %s", mockTokenResponse.TokenType, tokens.TokenType)
			}
			if tokens.ExpiresIn == nil || *tokens.ExpiresIn != *mockTokenResponse.ExpiresIn {
				t.Errorf("expected expires_in %d, got %v", *mockTokenResponse.ExpiresIn, tokens.ExpiresIn)
			}
			if tokens.RefreshToken == nil || *tokens.RefreshToken != *mockTokenResponse.RefreshToken {
				t.Errorf("expected refresh_token %s, got %v", *mockTokenResponse.RefreshToken, tokens.RefreshToken)
			}
		})

		t.Run("Includes redirect_uri in token request when provided", func(t *testing.T) {
			var calledBody string
			mockFetch = func(url string, req *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(req.Body)
				calledBody = string(body)
				t.Logf("request body: %s", calledBody) // 调试输出
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"access_token":"new-access-token","token_type":"Bearer","expires_in":3600,"refresh_token":"new-refresh-token"}`)),
				}, nil
			}
			provider.fetch = mockFetch

			_, err := provider.ExchangeAuthorizationCode(validClient, "test-code", &codeVerifier, &redirectURI, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.Contains(calledBody, "redirect_uri=https%3A%2F%2Fexample.com%2Fcallback") {
				t.Errorf("expected redirect_uri in body, got %s", calledBody)
			}
		})

		t.Run("Handles token exchange failure", func(t *testing.T) {
			mockFetch = func(url string, req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}
			provider.fetch = mockFetch

			_, err := provider.ExchangeAuthorizationCode(validClient, "test-code", &codeVerifier, nil, nil)
			t.Logf("error: %v", err) // 调试输出
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			var oauthErr oauthErrors.OAuthError
			if !errors.As(err, &oauthErr) {
				t.Errorf("expected error to be of type oauthErrors.OAuthError, got %T", err)
			}
			if oauthErr.ErrorCode != oauthErrors.ErrServerError.Error() {
				t.Errorf("expected OAuthError with code %s, got %s", oauthErrors.ErrServerError.Error(), oauthErr.ErrorCode)
			}
		})
	})

	t.Run("Client Registration", func(t *testing.T) {
		t.Run("Registers new client", func(t *testing.T) {
			mockFetch = func(url string, req *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(req.Body)
				t.Logf("register request body: %s", string(body)) // 调试输出
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"client_id":"new-client","client_secret":"new-secret","redirect_uris":["https://new-client.com/callback"]}`)),
				}, nil
			}
			provider.fetch = mockFetch

			newClient := auth.OAuthClientInformationFull{
				OAuthClientInformation: auth.OAuthClientInformation{
					ClientID: "new-client",
				},
				OAuthClientMetadata: auth.OAuthClientMetadata{
					RedirectURIs: []string{"https://new-client.com/callback"},
				},
			}
			result, err := provider.ClientsStore().RegisterClient(newClient)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.ClientID != newClient.ClientID {
				t.Errorf("expected client_id %s, got %s", newClient.ClientID, result.ClientID)
			}
		})

		t.Run("Handles registration failure", func(t *testing.T) {
			mockFetch = func(url string, req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}
			provider.fetch = mockFetch

			newClient := auth.OAuthClientInformationFull{
				OAuthClientInformation: auth.OAuthClientInformation{
					ClientID: "new-client",
				},
				OAuthClientMetadata: auth.OAuthClientMetadata{
					RedirectURIs: []string{"https://new-client.com/callback"},
				},
			}
			_, err := provider.ClientsStore().RegisterClient(newClient)
			t.Logf("error: %v", err) // 调试输出
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			var serverErr oauthErrors.OAuthError
			if !errors.As(err, &serverErr) {
				t.Errorf("expected error to be of type oauthErrors.OAuthError, got %T", err)
			}
			if serverErr.ErrorCode != oauthErrors.ErrServerError.Error() {
				t.Errorf("expected OAuthError with code %s, got %s", oauthErrors.ErrServerError.Error(), serverErr.ErrorCode)
			}
		})
	})

	t.Run("Token Revocation", func(t *testing.T) {
		t.Run("Revokes token", func(t *testing.T) {
			mockFetch = func(url string, req *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(req.Body)
				t.Logf("revoke request body: %s", string(body)) // 调试输出
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}
			provider.fetch = mockFetch

			err := provider.RevokeToken(validClient, auth.OAuthTokenRevocationRequest{
				Token:         "token-to-revoke",
				TokenTypeHint: "access_token",
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	})

	t.Run("Token Verification", func(t *testing.T) {
		t.Run("Verifies valid token", func(t *testing.T) {
			authInfo, err := provider.VerifyAccessToken("valid-token")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			t.Logf("authInfo: %+v", authInfo) // 调试输出
			if authInfo.ClientID != "test-client" {
				t.Errorf("expected clientId test-client, got %s", authInfo.ClientID)
			}
		})

		t.Run("Passes through InvalidTokenError", func(t *testing.T) {
			_, err := provider.VerifyAccessToken("invalid-token")
			t.Logf("error: %v", err) // 调试输出
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			var invalidTokenErr oauthErrors.OAuthError
			if !errors.As(err, &invalidTokenErr) {
				t.Errorf("expected error to be of type oauthErrors.OAuthError, got %T", err)
			}
			if invalidTokenErr.ErrorCode != oauthErrors.ErrInvalidToken.Error() {
				t.Errorf("expected OAuthError with code %s, got %s", oauthErrors.ErrInvalidToken.Error(), invalidTokenErr.ErrorCode)
			}
		})
	})
}
