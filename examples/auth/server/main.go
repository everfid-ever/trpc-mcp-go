package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	mcp "trpc.group/trpc-go/trpc-mcp-go"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/providers"
)

const hmacSecret = "demo-shared-secret"

// strPtr returns a pointer to the given string
func strPtr(s string) *string {
	return &s
}

// mustURL parses the given string as a URL and panics if invalid
func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func main() {
	log.Println("Starting OAuth server...")

	// Start the mock OAuth server first
	go startMockOAuthServer()
	time.Sleep(2 * time.Second)

	// Test the mock server
	resp, err := http.Get("http://localhost:3030/authorize?test=1")
	if err != nil {
		log.Fatalf("Mock OAuth server not ready: %v", err)
	}
	resp.Body.Close()
	log.Println("Mock OAuth server is ready")

	// Create OAuth Provider
	provider := providers.NewProxyOAuthServerProvider(providers.ProxyOptions{
		Endpoints: providers.ProxyEndpoints{
			AuthorizationURL: "http://localhost:3030/authorize",
			TokenURL:         "http://localhost:3030/token",
			RevocationURL:    "http://localhost:3030/revoke",
			RegistrationURL:  "http://localhost:3030/register",
		},

		VerifyAccessToken: func(token string) (*server.AuthInfo, error) {
			log.Printf("Verifying access token: %s", token[:20]+"...")
			ai, err := mockVerifyJWT(token)
			if err != nil {
				log.Printf("Token verification failed: %v", err)
				return nil, err
			}
			log.Printf("Token verified successfully: client_id=%s, scopes=%v", ai.ClientID, ai.Scopes)
			return &ai, nil
		},

		GetClient: func(clientID string) (*auth.OAuthClientInformationFull, error) {
			log.Printf("Getting client info for: %s", clientID)
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
					ClientSecret: "", // Public client, no key
				},
			}, nil
		},
	})

	// Create and start the MCP server
	mcpServer := mcp.NewServer(
		"Auth-Example-Server",
		"1.0.0",
		mcp.WithServerAddress(":3000"),
		mcp.WithServerPath("/mcp"),
		mcp.WithOAuthRoutes(mcp.OAuthRoutesConfig{
			Provider:        provider,
			IssuerURL:       mustURL("http://localhost:3030"),
			BaseURL:         mustURL("http://localhost:3000"),
			ScopesSupported: []string{"mcp.read", "mcp.write"},
		}),
		mcp.WithOAuthMetadata(mcp.OAuthMetadataConfig{
			ResourceServerURL: mustURL("http://localhost:3000"),
			ScopesSupported:   []string{"mcp.read", "mcp.write"},
			ResourceName:      strPtr("MCP Server"),
		}),
		mcp.WithBearerAuth(&mcp.BearerAuthConfig{
			Enabled:        true,
			RequiredScopes: []string{"mcp.read", "mcp.write"},
			Verifier: server.TokenVerifierFunc(func(ctx context.Context, token string) (server.AuthInfo, error) {
				log.Printf("Bearer auth: Verifying token: %s", token[:20]+"...")
				ai, err := mockVerifyJWT(token)
				if err != nil {
					log.Printf("Bearer auth: Token verification failed: %v", err)
					return server.AuthInfo{}, err
				}

				log.Printf("Bearer auth: Token verified - client_id=%s scopes=%v", ai.ClientID, ai.Scopes)
				return ai, nil
			}),
		}),
		mcp.WithHTTPContextFunc(
			mcp.NewAuthHTTPContextFunc(
				server.TokenVerifierFunc(func(ctx context.Context, token string) (server.AuthInfo, error) {
					log.Printf("HTTPContext: Verifying token: %s", token[:20]+"...")
					ai, err := mockVerifyJWT(token)
					if err != nil {
						log.Printf("HTTPContext: Token verification failed: %v", err)
						return server.AuthInfo{}, err
					}
					log.Printf("HTTPContext: Token verified - client_id=%s scopes=%v", ai.ClientID, ai.Scopes)
					return ai, nil
				}),
				mcp.ServerAuthConfig{
					Issuer:         "http://localhost:3030",
					Audience:       []string{"http://localhost:3000"},
					RequiredScopes: []string{"mcp.read", "mcp.write"},
				},
			),
		),

		mcp.WithAudit(&mcp.AuditConfig{
			Enabled:             true,
			Level:               "detailed",
			HashSensitiveData:   true,
			IncludeRequestBody:  true,
			IncludeResponseBody: true,
			EndpointPatterns:    []string{"/mcp/", "/authorize", "/token"},
			ExcludePatterns:     []string{"/healthz"},
		}),
	)

	greetTool := mcp.NewTool("greet",
		mcp.WithDescription("A simple greeting tool (OAuth protected)"),
		mcp.WithString("name", mcp.Description("Name to greet")))

	mcpServer.RegisterTool(greetTool, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name, _ := req.Params.Arguments["name"].(string)
		if name == "" {
			name = "World"
		}

		return mcp.NewTextResult(fmt.Sprintf("Hello, %s! (Authenticated via OAuth)", name)), nil
	})

	// Set up a graceful shutdown.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Start server (run in goroutine).
	go func() {
		log.Printf("MCP server started, listening on port 3000, path /mcp")
		if err := mcpServer.Start(); err != nil {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()
	// Wait for termination signal.
	<-stop
	log.Printf("Shutting down server...")
}

// startMockOAuthServer starts a simple mock OAuth server on port 3030
func startMockOAuthServer() {
	mux := http.NewServeMux()

	// Store the authorization code
	var authCode = "mock_auth_code_12345"

	// Authorize endpoint
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Mock OAuth: Authorization request: %s %s", r.Method, r.URL.RawQuery)

		// Handle test requests
		if r.URL.Query().Get("test") != "" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
			return
		}

		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		clientID := r.URL.Query().Get("client_id")
		codeChallenge := r.URL.Query().Get("code_challenge")
		scope := r.URL.Query().Get("scope")

		log.Printf("Mock OAuth: client_id=%s, scope=%s, code_challenge=%s", clientID, scope, codeChallenge[:10]+"...")

		if redirectURI == "" {
			http.Error(w, "Missing redirect_uri", http.StatusBadRequest)
			return
		}

		// Construct redirect URLs
		redirectURL := redirectURI + "?code=" + authCode
		if state != "" {
			redirectURL += "&state=" + state
		}

		log.Printf("Mock OAuth: Redirecting to %s", redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusFound)
	})

	// Token endpoint: supports authorization_code and refresh_token, and issues HS256 JWT
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Mock OAuth: Token exchange request received")
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Unified parsing form
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", http.StatusBadRequest)
			return
		}

		grantType := r.FormValue("grant_type")
		log.Printf("Mock OAuth: Grant type: %s", grantType)

		// Issuing HS256 JWT
		signJWT := func(claims jwt.MapClaims) (string, error) {
			tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			signed, err := tok.SignedString([]byte(hmacSecret))
			if err != nil {
				return "", err
			}
			log.Printf("Mock OAuth: Signed token with claims: %+v", claims)
			return signed, nil
		}

		switch grantType {
		case "authorization_code":
			clientID := r.FormValue("client_id")
			code := r.FormValue("code")
			redirectURI := r.FormValue("redirect_uri")
			codeVerifier := r.FormValue("code_verifier")

			log.Printf("Mock OAuth: Code exchange - client_id=%s, code=%s, redirect_uri=%s",
				clientID, code, redirectURI)

			// Basic parameter verification
			if clientID == "" || code == "" || redirectURI == "" || codeVerifier == "" {
				http.Error(w, "Missing required parameters for authorization_code", http.StatusBadRequest)
				return
			}

			now := time.Now()
			// Issue access_token (with iss/aud/iat/exp)
			accessToken, err := signJWT(jwt.MapClaims{
				"iss":       "http://localhost:3030",
				"aud":       "http://localhost:3000",
				"iat":       now.Unix(),
				"exp":       now.Add(1 * time.Hour).Unix(),
				"client_id": clientID,
				"sub":       clientID,
				"scope":     "mcp.read mcp.write",
			})
			if err != nil {
				log.Printf("Mock OAuth: Failed to sign access token: %v", err)
				http.Error(w, "failed to sign access token", http.StatusInternalServerError)
				return
			}

			// Issue refresh token
			refreshToken, err := signJWT(jwt.MapClaims{
				"iss":       "http://localhost:3030",
				"aud":       "http://localhost:3000",
				"iat":       now.Unix(),
				"exp":       now.Add(24 * time.Hour).Unix(),
				"client_id": clientID,
				"sub":       clientID,
				"typ":       "refresh",
			})
			if err != nil {
				log.Printf("Mock OAuth: Failed to sign refresh token: %v", err)
				http.Error(w, "failed to sign refresh token", http.StatusInternalServerError)
				return
			}

			resp := map[string]any{
				"access_token":  accessToken,
				"token_type":    "Bearer",
				"expires_in":    3600,
				"scope":         "mcp.read mcp.write",
				"refresh_token": refreshToken,
			}

			log.Printf("Mock OAuth: Returning token response")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

		case "refresh_token":
			rt := r.FormValue("refresh_token")
			if rt == "" {
				http.Error(w, "Missing refresh_token", http.StatusBadRequest)
				return
			}

			log.Printf("Mock OAuth: Refreshing token")

			// Parse and verify RT (HS256)
			parsed, err := jwt.Parse(rt, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
				}
				return []byte(hmacSecret), nil
			})
			if err != nil || !parsed.Valid {
				log.Printf("Mock OAuth: Invalid refresh token: %v", err)
				http.Error(w, "invalid refresh_token", http.StatusUnauthorized)
				return
			}
			claims, ok := parsed.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, "invalid refresh_token claims", http.StatusUnauthorized)
				return
			}

			// Extract client_id from RT claims (if not present, return public-client)
			clientID, _ := claims["client_id"].(string)
			if clientID == "" {
				clientID = "public-client"
			}

			now := time.Now()
			// New access_token
			newAT, err := signJWT(jwt.MapClaims{
				"iss":       "http://localhost:3030",
				"aud":       "http://localhost:3000",
				"iat":       now.Unix(),
				"exp":       now.Add(1 * time.Hour).Unix(),
				"client_id": clientID,
				"sub":       clientID,
				"scope":     "mcp.read mcp.write",
			})
			if err != nil {
				http.Error(w, "failed to sign access token", http.StatusInternalServerError)
				return
			}

			// New refresh_token
			newRT, err := signJWT(jwt.MapClaims{
				"iss":       "http://localhost:3030",
				"aud":       "http://localhost:3000",
				"iat":       now.Unix(),
				"exp":       now.Add(24 * time.Hour).Unix(),
				"client_id": clientID,
				"sub":       clientID,
				"typ":       "refresh",
			})
			if err != nil {
				http.Error(w, "failed to sign refresh token", http.StatusInternalServerError)
				return
			}

			resp := map[string]any{
				"access_token":  newAT,
				"token_type":    "Bearer",
				"expires_in":    3600,
				"scope":         "mcp.read mcp.write",
				"refresh_token": newRT,
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)

		default:
			http.Error(w, "unsupported_grant_type", http.StatusBadRequest)
			return
		}
	})

	// Revocation endpoint (optional)
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Mock OAuth: Token revocation request received")
		w.WriteHeader(http.StatusOK)
	})

	// Registration endpoint (optional)
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Mock OAuth: Client registration request received")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"client_id":      "test-client-id",
			"client_secret":  "test-secret",
			"client_name":    "demo-client",
			"scope":          "mcp.read mcp.write",
			"redirect_uris":  []string{"http://localhost:5173/callback"},
			"grant_types":    []string{"authorization_code", "refresh_token"},
			"response_types": []string{"code"},
		})
	})

	// Authorization Server Metadata (RFC 8414)
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Mock OAuth: Metadata request")
		meta := map[string]any{
			"issuer":                                "http://localhost:3030",
			"authorization_endpoint":                "http://localhost:3030/authorize",
			"token_endpoint":                        "http://localhost:3030/token",
			"registration_endpoint":                 "http://localhost:3030/register",
			"revocation_endpoint":                   "http://localhost:3030/revoke",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
			"scopes_supported":                      []string{"mcp.read", "mcp.write"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meta)
	})

	// Compatible with OIDC discovery (many clients will try this path simultaneously)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Mock OAuth: OIDC configuration request")
		cfg := map[string]any{
			"issuer":                                "http://localhost:3030",
			"authorization_endpoint":                "http://localhost:3030/authorize",
			"token_endpoint":                        "http://localhost:3030/token",
			"registration_endpoint":                 "http://localhost:3030/register",
			"revocation_endpoint":                   "http://localhost:3030/revoke",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
			"scopes_supported":                      []string{"mcp.read", "mcp.write"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	})

	server := &http.Server{
		Addr:    ":3030",
		Handler: mux,
	}

	log.Println("Mock OAuth server starting on http://localhost:3030")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("Mock OAuth server error: %v", err)
	}
}

// mockVerifyJWT verifies a JWT using HMAC and extracts AuthInfo
func mockVerifyJWT(token string) (server.AuthInfo, error) {
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(hmacSecret), nil
	})
	if err != nil || !parsed.Valid {
		return server.AuthInfo{}, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return server.AuthInfo{}, fmt.Errorf("invalid claims")
	}

	// Parse client_id or sub
	var clientID string
	if cid, _ := claims["client_id"].(string); cid != "" {
		clientID = cid
	}
	if sub, _ := claims["sub"].(string); sub != "" {
		clientID = sub
	}

	// Parse scope
	scopeStr, _ := claims["scope"].(string)
	var scopes []string
	if scopeStr != "" {
		scopes = strings.Split(scopeStr, " ")
	}

	// Pares exp
	var expPtr *int64
	if v, ok := claims["exp"].(float64); ok {
		vv := int64(v)
		expPtr = &vv
	}

	// Make sure that Extra contains sub + client_id
	if claims["client_id"] == nil && clientID != "" {
		claims["client_id"] = clientID
	}
	if claims["sub"] == nil && clientID != "" {
		claims["sub"] = clientID
	}

	return server.AuthInfo{
		Token:     token,
		ClientID:  clientID,
		Scopes:    scopes,
		ExpiresAt: expPtr,
		Extra: map[string]any{
			"client_id": clientID,
			"sub":       clientID,
			"scope":     strings.Join(scopes, " "),
			"exp":       expPtr,
		},
	}, nil
}
