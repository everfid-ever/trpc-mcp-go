package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	srv "trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	oauth "trpc.group/trpc-go/trpc-mcp-go/internal/errors"
)

// mockVerifier is a test double for TokenVerifierInterface that records the
// last token and delegates verification to a provided function
type mockVerifier struct {
	verify func(ctx context.Context, token string) (srv.AuthInfo, error)
	last   string
}

// VerifyAccessToken records the token and forwards verification to the mock function
func (m *mockVerifier) VerifyAccessToken(ctx context.Context, token string) (srv.AuthInfo, error) {
	m.last = token
	return m.verify(ctx, token)
}

// runWithMiddleware builds a request, executes the BearerAuth middleware with the
// provided options and Authorization header, and returns the recorder and whether
// the next handler was called
func runWithMiddleware(t *testing.T, options BearerAuthMiddlewareOptions, authHeader string) (rec *httptest.ResponseRecorder, nextCalled bool) {
	t.Helper()
	nextCalled = false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		// return 200 to assert the middleware allowed the reques
		w.WriteHeader(http.StatusOK)
	})

	handler := RequireBearerAuth(options)(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec, nextCalled
}

// decodeOAuthResp parses the OAuth error response body into OAuthErrorResponse
func decodeOAuthResp(t *testing.T, rec *httptest.ResponseRecorder) *oauth.OAuthErrorResponse {
	t.Helper()
	var body oauth.OAuthErrorResponse
	_ = json.NewDecoder(rec.Body).Decode(&body)
	return &body
}

func TestRequireBearerAuth_ValidToken(t *testing.T) {
	exp := time.Now().Add(1 * time.Hour).Unix()
	valid := srv.AuthInfo{Token: "valid-token", ClientID: "client-123", Scopes: []string{"read", "write"}, ExpiresAt: &exp}
	mv := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) { return valid, nil }}

	rec, nextCalled := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv}, "Bearer valid-token")

	if mv.last != "valid-token" {
		t.Fatalf("expected token 'valid-token', got %q", mv.last)
	}
	if !nextCalled {
		t.Fatalf("expected next to be called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
}

func TestRequireBearerAuth_ExpiredToken(t *testing.T) {
	expiredSeconds := []int{100, 0}

	for _, seconds := range expiredSeconds {
		t.Run(fmt.Sprintf("expired_%d_seconds_ago", seconds), func(t *testing.T) {
			// Set the expiration time to the current time minus the specified number of seconds
			exp := time.Now().Add(time.Duration(-seconds) * time.Second).Unix()
			expired := srv.AuthInfo{
				Token:     "expired-token",
				ClientID:  "client-123",
				Scopes:    []string{"read", "write"},
				ExpiresAt: &exp,
			}
			mv := &mockVerifier{
				verify: func(ctx context.Context, token string) (srv.AuthInfo, error) {
					return expired, nil
				},
			}

			rec, nextCalled := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv}, "Bearer expired-token")

			if mv.last != "expired-token" {
				t.Fatalf("expected token 'expired-token', got %q", mv.last)
			}
			if nextCalled {
				t.Fatalf("expected next not to be called")
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d", rec.Code)
			}
			hdr := rec.Header().Get("WWW-Authenticate")
			if !strings.Contains(hdr, `error="invalid_token"`) || !strings.Contains(hdr, "Token has expired") {
				t.Fatalf("unexpected WWW-Authenticate: %q", hdr)
			}
			body := decodeOAuthResp(t, rec)
			if body.Error != "invalid_token" || body.ErrorDescription != "Token has expired" {
				t.Fatalf("unexpected body: %+v", body)
			}
		})
	}
}

func TestRequireBearerAuth_NoExpiration(t *testing.T) {
	// case1: nil
	t.Run("ExpiresAt=nil", func(t *testing.T) {
		noexp := srv.AuthInfo{Token: "t1", ClientID: "c", Scopes: []string{"read"}, ExpiresAt: nil}
		mv := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) { return noexp, nil }}
		rec, nextCalled := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv}, "Bearer t1")
		if nextCalled || rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 without next, got %d next=%v", rec.Code, nextCalled)
		}
		if hdr := rec.Header().Get("WWW-Authenticate"); !strings.Contains(hdr, `error="invalid_token"`) || !strings.Contains(hdr, "Token has no expiration time") {
			t.Fatalf("unexpected WWW-Authenticate: %q", hdr)
		}
		body := decodeOAuthResp(t, rec)
		if body.Error != "invalid_token" || body.ErrorDescription != "Token has no expiration time" {
			t.Fatalf("unexpected body: %+v", body)
		}
	})

	// case2: 0
	t.Run("ExpiresAt=0", func(t *testing.T) {
		zero := int64(0)
		noexp2 := srv.AuthInfo{Token: "t2", ClientID: "c", Scopes: []string{"read"}, ExpiresAt: &zero}
		mv2 := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) { return noexp2, nil }}
		rec2, nextCalled2 := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv2}, "Bearer t2")
		if nextCalled2 || rec2.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 without next, got %d next=%v", rec2.Code, nextCalled2)
		}
		if hdr := rec2.Header().Get("WWW-Authenticate"); !strings.Contains(hdr, `error="invalid_token"`) || !strings.Contains(hdr, "Token has no expiration time") {
			t.Fatalf("unexpected WWW-Authenticate: %q", hdr)
		}
		body := decodeOAuthResp(t, rec2)
		if body.Error != "invalid_token" || body.ErrorDescription != "Token has no expiration time" {
			t.Fatalf("unexpected body: %+v", body)
		}
	})
}
func TestRequireBearerAuth_NonExpiredAccepted(t *testing.T) {
	exp := time.Now().Add(1 * time.Hour).Unix()
	ai := srv.AuthInfo{Token: "valid", ClientID: "c", Scopes: []string{"read"}, ExpiresAt: &exp}
	mv := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) { return ai, nil }}
	rec, nextCalled := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv}, "Bearer valid")
	if rec.Code != http.StatusOK || !nextCalled {
		t.Fatalf("expected 200 and next called, got %d next=%v", rec.Code, nextCalled)
	}
}

func TestRequireBearerAuth_RequiredScopes(t *testing.T) {
	exp := time.Now().Add(1 * time.Hour).Unix()
	ai := srv.AuthInfo{Token: "valid", ClientID: "c", Scopes: []string{"read"}, ExpiresAt: &exp}
	mv := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) { return ai, nil }}
	rec, nextCalled := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv, RequiredScopes: []string{"read", "write"}}, "Bearer valid")

	if mv.last != "valid" {
		t.Fatalf("expected verifier to be called with token 'valid', got %q", mv.last)
	}
	if nextCalled || rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 and next not called, got %d next=%v", rec.Code, nextCalled)
	}
	hdr := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(hdr, `error="insufficient_scope"`) {
		t.Fatalf("unexpected WWW-Authenticate: %q", hdr)
	}
	body := decodeOAuthResp(t, rec)
	if body.Error != "insufficient_scope" || body.ErrorDescription != "Insufficient scope" {
		t.Fatalf("unexpected body: %+v", body)
	}
}

func TestRequireBearerAuth_AcceptsAllRequiredScopes(t *testing.T) {
	exp := time.Now().Add(1 * time.Hour).Unix()
	ai := srv.AuthInfo{Token: "valid", ClientID: "c", Scopes: []string{"read", "write", "admin"}, ExpiresAt: &exp}
	mv := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) { return ai, nil }}
	rec, nextCalled := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv, RequiredScopes: []string{"read", "write"}}, "Bearer valid")
	if rec.Code != http.StatusOK || !nextCalled {
		t.Fatalf("expected 200 and next called, got %d next=%v", rec.Code, nextCalled)
	}
}

func TestRequireBearerAuth_MissingAuthorization(t *testing.T) {
	mv := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) { return srv.AuthInfo{}, nil }}
	rec, nextCalled := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv}, "")
	if mv.last != "" {
		t.Fatalf("verifier should not be called")
	}
	if nextCalled || rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without next, got %d next=%v", rec.Code, nextCalled)
	}
	// 检查完整的 WWW-Authenticate 头
	expectedHeader := `Bearer error="invalid_token", error_description="Missing Authorization header"`
	hdr := rec.Header().Get("WWW-Authenticate")
	if hdr != expectedHeader {
		t.Fatalf("expected WWW-Authenticate: %q, got %q", expectedHeader, hdr)
	}
	// 检查响应体
	body := decodeOAuthResp(t, rec)
	if body.Error != "invalid_token" || body.ErrorDescription != "Missing Authorization header" {
		t.Fatalf("expected body error=\"invalid_token\", error_description=\"Missing Authorization header\", got %+v", body)
	}
}

func TestRequireBearerAuth_InvalidAuthorizationFormat(t *testing.T) {
	mv := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) { return srv.AuthInfo{}, nil }}
	rec, nextCalled := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv}, "InvalidFormat")
	if mv.last != "" {
		t.Fatalf("verifier should not be called")
	}
	if nextCalled || rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without next, got %d next=%v", rec.Code, nextCalled)
	}
	// 验证 WWW-Authenticate 头的完整字符串
	expectedHeader := `Bearer error="invalid_token", error_description="Invalid Authorization header format, expected 'Bearer TOKEN'"`
	if hdr := rec.Header().Get("WWW-Authenticate"); hdr != expectedHeader {
		t.Fatalf("expected WWW-Authenticate: %q, got %q", expectedHeader, hdr)
	}
	// 验证响应体
	body := decodeOAuthResp(t, rec)
	if body.Error != "invalid_token" || body.ErrorDescription != "Invalid Authorization header format, expected 'Bearer TOKEN'" {
		t.Fatalf("unexpected body: %+v", body)
	}
}

func TestRequireBearerAuth_VerifierErrors(t *testing.T) {
	t.Run("invalid_token -> 401", func(t *testing.T) {
		mv := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) {
			return srv.AuthInfo{}, oauth.NewOAuthError(oauth.ErrInvalidToken, "Token expired", "")
		}}
		rec, nextCalled := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv}, "Bearer invalid-token")
		if mv.last != "invalid-token" {
			t.Fatalf("expected token 'invalid-token', got %q", mv.last)
		}
		if nextCalled || rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 without next, got %d next=%v", rec.Code, nextCalled)
		}
		hdr := rec.Header().Get("WWW-Authenticate")
		if !strings.Contains(hdr, `error="invalid_token"`) || !strings.Contains(hdr, "Token expired") {
			t.Fatalf("unexpected WWW-Authenticate: %q", hdr)
		}
	})

	t.Run("insufficient_scope -> 403", func(t *testing.T) {
		mv := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) {
			return srv.AuthInfo{}, oauth.NewOAuthError(oauth.ErrInsufficientScope, "Required scopes: read, write", "")
		}}
		rec, nextCalled := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv}, "Bearer valid-token")
		if mv.last != "valid-token" {
			t.Fatalf("expected token 'valid-token', got %q", mv.last)
		}
		if nextCalled || rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 without next, got %d next=%v", rec.Code, nextCalled)
		}
		hdr := rec.Header().Get("WWW-Authenticate")
		if !strings.Contains(hdr, `error="insufficient_scope"`) {
			t.Fatalf("unexpected WWW-Authenticate: %q", hdr)
		}
		body := decodeOAuthResp(t, rec)
		if body.Error != "insufficient_scope" || body.ErrorDescription != "Required scopes: read, write" {
			t.Fatalf("unexpected body: %+v", body)
		}
	})

	t.Run("server_error -> 500", func(t *testing.T) {
		mv := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) {
			return srv.AuthInfo{}, oauth.NewOAuthError(oauth.ErrServerError, "Internal server issue", "")
		}}
		rec, nextCalled := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv}, "Bearer valid-token")
		if mv.last != "valid-token" {
			t.Fatalf("expected token 'valid-token', got %q", mv.last)
		}
		if nextCalled || rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 without next, got %d next=%v", rec.Code, nextCalled)
		}
		if hdr := rec.Header().Get("WWW-Authenticate"); hdr != "" {
			t.Fatalf("expected no WWW-Authenticate header, got %q", hdr)
		}
		body := decodeOAuthResp(t, rec)
		if body.Error != "server_error" || body.ErrorDescription != "Internal server issue" {
			t.Fatalf("unexpected body: %+v", body)
		}
	})

	t.Run("generic oauth error -> 400", func(t *testing.T) {
		mv := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) {
			return srv.AuthInfo{}, oauth.NewOAuthError(oauth.ErrInvalidRequest, "Some OAuth error", "")
		}}
		rec, nextCalled := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv}, "Bearer valid-token")
		if nextCalled || rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 without next, got %d next=%v", rec.Code, nextCalled)
		}
		if mv.last != "valid-token" {
			t.Fatalf("expected token 'valid-token', got %q", mv.last)
		}
		body := decodeOAuthResp(t, rec)
		if body.Error != "invalid_request" || body.ErrorDescription != "Some OAuth error" {
			t.Fatalf("unexpected body: %+v", body)
		}
	})

	t.Run("unexpected error -> 500", func(t *testing.T) {
		mv := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) {
			return srv.AuthInfo{}, fmt.Errorf("unexpected error")
		}}
		rec, nextCalled := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv}, "Bearer valid-token")
		if mv.last != "valid-token" {
			t.Fatalf("expected token 'valid-token', got %q", mv.last)
		}
		if nextCalled {
			t.Fatalf("expected next not to be called")
		}
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
		body := decodeOAuthResp(t, rec)
		if body.Error != "server_error" || body.ErrorDescription != "Internal Server Error" {
			t.Fatalf("unexpected body: %+v", body)
		}
		if hdr := rec.Header().Get("WWW-Authenticate"); hdr != "" {
			t.Fatalf("expected no WWW-Authenticate header, got %q", hdr)
		}
	})
}

func TestRequireBearerAuth_WithResourceMetadata(t *testing.T) {
	url := "https://api.example.com/.well-known/oauth-protected-resource"

	t.Run("401 includes resource_metadata when missing header", func(t *testing.T) {
		mv := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) { return srv.AuthInfo{}, nil }}
		rec, _ := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv, ResourceMetadataURL: &url}, "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
		if mv.last != "" {
			t.Fatalf("verifier should not be called, got token %q", mv.last)
		}
		hdr := rec.Header().Get("WWW-Authenticate")
		expectedHdr := `Bearer error="invalid_token", error_description="Missing Authorization header", resource_metadata="` + url + `"`
		if hdr != expectedHdr {
			t.Fatalf("expected WWW-Authenticate: %q, got %q", expectedHdr, hdr)
		}
	})

	t.Run("401 includes resource_metadata when verifier returns invalid_token", func(t *testing.T) {
		mv := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) {
			return srv.AuthInfo{}, oauth.NewOAuthError(oauth.ErrInvalidToken, "Token expired", "")
		}}
		rec, _ := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv, ResourceMetadataURL: &url}, "Bearer bad")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
		hdr := rec.Header().Get("WWW-Authenticate")
		if !strings.Contains(hdr, `resource_metadata="`+url+`"`) {
			t.Fatalf("resource_metadata missing in header: %q", hdr)
		}
	})

	t.Run("403 includes resource_metadata for insufficient scope", func(t *testing.T) {
		mv := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) {
			return srv.AuthInfo{}, oauth.NewOAuthError(oauth.ErrInsufficientScope, "Required scopes: admin", "")
		}}
		rec, _ := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv, ResourceMetadataURL: &url}, "Bearer t")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
		if hdr := rec.Header().Get("WWW-Authenticate"); !strings.Contains(hdr, `resource_metadata="`+url+`"`) {
			t.Fatalf("resource_metadata missing in header: %q", hdr)
		}
	})

	t.Run("expired token includes resource_metadata", func(t *testing.T) {
		exp := time.Now().Add(-100 * time.Second).Unix()
		ai := srv.AuthInfo{Token: "expired", ClientID: "c", Scopes: []string{"read", "write"}, ExpiresAt: &exp}
		mv := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) { return ai, nil }}
		rec, _ := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv, ResourceMetadataURL: &url}, "Bearer expired")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
		if hdr := rec.Header().Get("WWW-Authenticate"); !strings.Contains(hdr, `resource_metadata="`+url+`"`) {
			t.Fatalf("resource_metadata missing in header: %q", hdr)
		}
	})

	t.Run("scope check fail includes resource_metadata", func(t *testing.T) {
		exp := time.Now().Add(1 * time.Hour).Unix()
		ai := srv.AuthInfo{Token: "ok", ClientID: "c", Scopes: []string{"read"}, ExpiresAt: &exp}
		mv := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) { return ai, nil }}
		rec, _ := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv, RequiredScopes: []string{"read", "write"}, ResourceMetadataURL: &url}, "Bearer ok")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
		if hdr := rec.Header().Get("WWW-Authenticate"); !strings.Contains(hdr, `resource_metadata="`+url+`"`) {
			t.Fatalf("resource_metadata missing in header: %q", hdr)
		}
	})

	t.Run("server error does not include WWW-Authenticate header", func(t *testing.T) {
		url := "https://api.example.com/.well-known/oauth-protected-resource"
		mv := &mockVerifier{verify: func(ctx context.Context, token string) (srv.AuthInfo, error) {
			return srv.AuthInfo{}, oauth.NewOAuthError(oauth.ErrServerError, "Internal server issue", "")
		}}
		rec, nextCalled := runWithMiddleware(t, BearerAuthMiddlewareOptions{Verifier: mv, ResourceMetadataURL: &url}, "Bearer valid-token")
		if mv.last != "valid-token" {
			t.Fatalf("expected token 'valid-token', got %q", mv.last)
		}
		if nextCalled {
			t.Fatalf("expected next not to be called")
		}
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
		if hdr := rec.Header().Get("WWW-Authenticate"); hdr != "" {
			t.Fatalf("expected no WWW-Authenticate header, got %q", hdr)
		}
		body := decodeOAuthResp(t, rec)
		if body.Error != "server_error" || body.ErrorDescription != "Internal server issue" {
			t.Fatalf("expected body {error: \"server_error\", error_description: \"Internal server issue\"}, got %+v", body)
		}
	})
}
