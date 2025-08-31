package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/pkce"

	mcp "trpc.group/trpc-go/trpc-mcp-go"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/client"
)

func strPtr(s string) *string { return &s }

var (
	codeCh       = make(chan string, 1)
	codeVerifier string
)

func main() {
	log.Println("Starting OAuth client...")

	// Generate PKCE parameters
	pkceChallenge, err := pkce.GeneratePKCEChallenge()
	if err != nil {
		log.Fatalf("Failed to generate PKCE challenge: %v", err)
	}

	codeVerifier = pkceChallenge.CodeVerifier
	challenge := pkceChallenge.CodeChallenge

	log.Printf("Generated PKCE verifier: %s", codeVerifier)
	log.Printf("Generated PKCE challenge: %s", challenge)

	// Fix: Use correct authorization server address (port 3000, since MCP server handles OAuth routes)
	authURL := "http://localhost:3000/authorize" +
		"?response_type=code" +
		"&client_id=test-client-id" +
		"&redirect_uri=http://localhost:5173/callback" +
		"&scope=mcp.read" +
		"&code_challenge=" + url.QueryEscape(challenge) +
		"&code_challenge_method=S256"

	log.Println("Please open the following URL in your browser:")
	log.Println(authURL)

	// Start callback server
	go startCallbackServer()

	log.Println("Waiting for authorization...")

	// Wait for code with timeout
	select {
	case code := <-codeCh:
		log.Println("Authorization code received:", code)

		token, err := exchangeToken("http://localhost:3030/token", code, "http://localhost:5173/callback")
		if err != nil {
			log.Fatalf("Error exchanging token: %v", err)
		}

		log.Println("Access token received:", token.AccessToken)

		// Test MCP connection
		if err := testMCPConnection(token); err != nil {
			log.Printf("MCP connection test failed: %v", err)
		} else {
			log.Println("MCP connection successful!")
		}

	case <-time.After(5 * time.Minute):
		log.Fatal("Timeout waiting for authorization")
	}
}

func exchangeToken(tokenURL, code, redirectURI string) (*auth.OAuthTokens, error) {
	log.Println("Exchanging authorization code for access token...")

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", "test-client-id")
	data.Set("client_secret", "test-secret")
	data.Set("code_verifier", codeVerifier)

	log.Println("Token exchange parameters:")
	for key, values := range data {
		log.Printf("  %s: %v", key, values)
	}

	req, _ := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	log.Printf("Making token request to: %s", tokenURL)
	log.Printf("Request headers: %v", req.Header)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	log.Printf("Token response status: %d", resp.StatusCode)
	log.Printf("Token response body: %s", string(body))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status: %d, body: %s", resp.StatusCode, string(body))
	}

	var token auth.OAuthTokens
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %v", err)
	}

	return &token, nil
}

func startCallbackServer() {
	mux := http.NewServeMux()

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Callback received: %s", r.URL.RawQuery)

		code := r.URL.Query().Get("code")
		if code == "" {
			errorDesc := r.URL.Query().Get("error_description")
			if errorDesc == "" {
				errorDesc = "No authorization code received"
			}
			log.Printf("Error: %s", errorDesc)
			http.Error(w, errorDesc, http.StatusBadRequest)
			return
		}

		select {
		case codeCh <- code:
			fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head><title>Authorization Complete</title></head>
<body>
    <h1>Authorization Successful!</h1>
    <p>You can close this window and return to the terminal.</p>
</body>
</html>`)
		default:
			fmt.Fprintf(w, "Authorization code already received")
		}
	})

	server := &http.Server{
		Addr:    ":5173",
		Handler: mux,
	}

	log.Println("Callback server starting on http://localhost:5173")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("Callback server error: %v", err)
	}
}

func testMCPConnection(token *auth.OAuthTokens) error {
	log.Println("Testing MCP connection with OAuth token...")

	oauthProvider := client.NewInMemoryOAuthClientProvider(
		"http://localhost:5173/callback",
		auth.OAuthClientMetadata{
			ClientName:              strPtr("demo-client"),
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			TokenEndpointAuthMethod: "client_secret_post",
			RedirectURIs:            []string{"http://localhost:5173/callback"},
		},
		nil,
	)

	if err := oauthProvider.SaveTokens(*token); err != nil {
		return fmt.Errorf("failed to save tokens: %v", err)
	}

	ctx := context.Background()

	// 创建 MCP 客户端，确保使用正确的 MCP 端点
	c, err := mcp.NewClient(
		"http://localhost:3000/mcp",
		mcp.Implementation{Name: "demo", Version: "0.1.0"},
		mcp.WithOAuthClientProvider(oauthProvider),
	)
	if err != nil {
		return fmt.Errorf("failed to create MCP client: %v", err)
	}

	log.Println("Attempting MCP initialization...")

	// 初始化 MCP 连接
	initResult, err := c.Initialize(ctx, nil)
	if err != nil {
		return fmt.Errorf("MCP initialization failed: %v", err)
	}

	log.Printf("MCP initialization successful: %+v", initResult)

	return nil
}
