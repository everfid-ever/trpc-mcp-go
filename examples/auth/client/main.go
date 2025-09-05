package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	mcp "trpc.group/trpc-go/trpc-mcp-go"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
)

const (
	// Base origin of the MCP resource server
	serverURL = "http://localhost:3000"

	// Well-known OAuth protected resource metadata endpoint
	resourceMetadataURL = "http://localhost:3000/.well-known/oauth-protected-resource"

	// Local redirect URI that receives the authorization code
	redirectURL = "http://localhost:5173/callback"

	// Requested scopes for this demo
	scope = "mcp.read mcp.write"

	// HTTP listen address for the local callback server
	callbackListenAddr = ":5173"

	// MCP entry endpoint used by the SDK client
	mcpEndpoint = "http://localhost:3000/mcp/"
)

func main() {
	log.Println("Starting OAuth client...")

	// Configure the auth flow used by the MCP SDK
	authFlow := mcp.AuthFlowConfig{
		ServerURL: serverURL,
		ClientMetadata: auth.OAuthClientMetadata{
			ClientName:              strPtr("demo-client"),
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			TokenEndpointAuthMethod: "client_secret_post",
			RedirectURIs:            []string{redirectURL},
			Scope:                   strPtr(scope),
		},
		ResourceMetadataURL: strPtr(resourceMetadataURL),
		RedirectURL:         redirectURL,
		Scope:               strPtr(scope),
		OnRedirect: func(u *url.URL) error {
			log.Printf("Authorization required. Opening: %s", u.String())
			return nil
		},
	}

	// Create the MCP client with auth flow enabled
	client, err := mcp.NewClient(
		mcpEndpoint,
		mcp.Implementation{Name: "Auth-Example-Client", Version: "0.1.0"},
		mcp.WithAuthFlow(authFlow),
	)
	if err != nil {
		log.Fatalf("failed to create MCP client: %v", err)
	}

	// Start the local HTTP callback server to capture the authorization code
	authDone := make(chan struct{}, 1)
	cbServer := startCallbackServer(client, authDone)
	defer shutdownServer(cbServer)

	// First initialize will typically request user authorization
	log.Println("Initialize #1 (triggering authorization flow) ...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := client.Initialize(ctx, &mcp.InitializeRequest{}); err != nil {
		log.Printf("Initialize #1 returned (expected): %v", err)
	}

	// Wait for the browser redirect to complete the code exchange
	select {
	case <-authDone:
		log.Println("Authorization completed via callback")
	case <-time.After(3 * time.Minute):
		log.Fatal("timeout waiting for OAuth callback")
	}

	// Small delay to ensure token persistence
	time.Sleep(2 * time.Second)

	// Second initialize should succeed using the stored tokens
	log.Println("Initialize #2 (with valid tokens) ...")
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()

	initResp, err := client.Initialize(ctx2, &mcp.InitializeRequest{})
	if err != nil {
		log.Fatalf("Initialize #2 failed: %v", err)
	}
	log.Printf("MCP initialization successful. Server info: %+v", initResp.ServerInfo)
}

// startCallbackServer runs an HTTP server that handles /callback and completes the OAuth flow via the SDK
func startCallbackServer(c *mcp.Client, done chan<- struct{}) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Callback received: %s", r.URL.RawQuery)

		code := r.URL.Query().Get("code")
		if code == "" {
			log.Printf("Missing code parameter")
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}

		state := r.URL.Query().Get("state")
		log.Printf("Received callback with code: %s, state: %s", code[:10]+"...", state[:10]+"...")

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		if err := c.CompleteAuthFlow(ctx, code); err != nil {
			log.Printf("Complete auth flow failed: %v", err)
			http.Error(w, fmt.Sprintf("complete auth failed: %v", err), http.StatusBadRequest)
			return
		}

		log.Println("Auth flow completed successfully")
		_, _ = w.Write([]byte("Authorization complete!"))

		// Notify the main goroutine
		select {
		case done <- struct{}{}:
		default:
		}
	})

	srv := &http.Server{
		Addr:              callbackListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadTimeout:       10 * time.Second,
	}

	go func() {
		log.Printf("Callback server listening on %s", callbackListenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("callback server error: %v", err)
		}
	}()
	return srv
}

// shutdownServer gracefully stops the HTTP server within a short timeout
func shutdownServer(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}
}

// strPtr returns a pointer to s
func strPtr(s string) *string {
	return &s
}
