// Tencent is pleased to support the open source community by making trpc-mcp-go available.
//
// Copyright (C) 2025 Tencent.  All rights reserved.
//
// trpc-mcp-go is licensed under the Apache License Version 2.0.

package handler

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	as "trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
)

const validChallenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

type oauthErrResp struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

type mockProvider struct {
	store         *as.OAuthClientsStore
	authorizeFunc func(client auth.OAuthClientInformationFull, params as.AuthorizationParams, w http.ResponseWriter, r *http.Request) error
}

func (m *mockProvider) ClientsStore() *as.OAuthClientsStore { return m.store }

func (m *mockProvider) Authorize(client auth.OAuthClientInformationFull, params as.AuthorizationParams, w http.ResponseWriter, r *http.Request) error {
	if m.authorizeFunc != nil {
		return m.authorizeFunc(client, params, w, r)
	}
	u, _ := url.Parse(params.RedirectURI)
	q := u.Query()
	q.Set("code", "abc123")
	if params.State != "" {
		q.Set("state", params.State)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
	return nil
}

func (m *mockProvider) ChallengeForAuthorizationCode(client auth.OAuthClientInformationFull, authorizationCode string) (string, error) {
	return "", nil
}
func (m *mockProvider) ExchangeAuthorizationCode(client auth.OAuthClientInformationFull, authorizationCode string, codeVerifier *string, redirectUri *string, resource *url.URL) (*auth.OAuthTokens, error) {
	return nil, nil
}
func (m *mockProvider) ExchangeRefreshToken(client auth.OAuthClientInformationFull, refreshToken string, scopes []string, resource *url.URL) (*auth.OAuthTokens, error) {
	return nil, nil
}
func (m *mockProvider) VerifyAccessToken(token string) (*as.AuthInfo, error) { return nil, nil }

// SupportTokenRevocation（可选接口）——实现一个空方法以满足嵌入式接口
func (m *mockProvider) RevokeToken(client auth.OAuthClientInformationFull, request auth.OAuthTokenRevocationRequest) error {
	return nil
}

func makeStoreWithClient(c *auth.OAuthClientInformationFull) *as.OAuthClientsStore {
	return as.NewOAuthClientStore(func(id string) (*auth.OAuthClientInformationFull, error) {
		if c != nil && c.ClientID == id {
			return c, nil
		}
		return nil, nil
	})
}

func makeClient(id string, redirects []string, scope *string) *auth.OAuthClientInformationFull {
	return &auth.OAuthClientInformationFull{
		OAuthClientInformation: auth.OAuthClientInformation{
			ClientID: id,
		},
		OAuthClientMetadata: auth.OAuthClientMetadata{
			RedirectURIs: redirects,
			Scope:        scope,
		},
	}
}

func newGET(urlStr string) *http.Request {
	return httptest.NewRequest(http.MethodGet, urlStr, nil)
}

func newPOST(urlStr string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, urlStr, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestAuthorization_SuccessGET(t *testing.T) {
	scope := "read write"
	client := makeClient("c1", []string{"https://app.example.com/cb"}, &scope)
	mp := &mockProvider{store: makeStoreWithClient(client)}

	h := AuthorizationHandler(AuthorizationHandlerOptions{Provider: mp})

	qs := url.Values{
		"client_id":             {"c1"},
		"redirect_uri":          {"https://app.example.com/cb"},
		"response_type":         {"code"},
		"code_challenge":        {validChallenge},
		"code_challenge_method": {"S256"},
		"state":                 {"st-123"},
		"scope":                 {"read"},
	}
	req := newGET("/authorize?" + qs.Encode())
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	loc := rr.Header().Get("Location")
	u, err := url.Parse(loc)
	require.NoError(t, err)
	q := u.Query()
	assert.Equal(t, "abc123", q.Get("code"))
	assert.Equal(t, "st-123", q.Get("state"))
}

func TestAuthorization_MissingClientID_JSON400(t *testing.T) {
	client := makeClient("c1", []string{"https://app.example.com/cb"}, nil)
	mp := &mockProvider{store: makeStoreWithClient(client)}
	h := AuthorizationHandler(AuthorizationHandlerOptions{Provider: mp})

	req := newGET("/authorize?redirect_uri=https://app.example.com/cb")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp oauthErrResp
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "invalid request", resp.Error)
	assert.NotEmpty(t, resp.ErrorDescription)
}

func TestAuthorization_UnregisteredRedirect_JSON400(t *testing.T) {
	client := makeClient("c1", []string{"https://app.example.com/cb"}, nil)
	mp := &mockProvider{store: makeStoreWithClient(client)}
	h := AuthorizationHandler(AuthorizationHandlerOptions{Provider: mp})

	req := newGET("/authorize?client_id=c1&redirect_uri=https://evil.example.com/cb")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp oauthErrResp
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "invalid request", resp.Error)
	assert.Contains(t, strings.ToLower(resp.ErrorDescription), "redirect")
}

func TestAuthorization_MultipleRedirects_RequireExplicit_JSON400(t *testing.T) {
	client := makeClient("c1", []string{"https://a/cb", "https://b/cb"}, nil)
	mp := &mockProvider{store: makeStoreWithClient(client)}
	h := AuthorizationHandler(AuthorizationHandlerOptions{Provider: mp})

	req := newGET("/authorize?client_id=c1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var resp oauthErrResp
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "invalid request", resp.Error)
	assert.Contains(t, strings.ToLower(resp.ErrorDescription), "redirect")
}

func TestAuthorization_InvalidScope_302_WithState(t *testing.T) {
	scope := "read write"
	client := makeClient("c1", []string{"https://app.example.com/cb"}, &scope)
	mp := &mockProvider{store: makeStoreWithClient(client)}
	h := AuthorizationHandler(AuthorizationHandlerOptions{Provider: mp})

	qs := url.Values{
		"client_id":             {"c1"},
		"redirect_uri":          {"https://app.example.com/cb"},
		"response_type":         {"code"},
		"code_challenge":        {validChallenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"delete"},
		"state":                 {"keep-me"},
	}
	req := newGET("/authorize?" + qs.Encode())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	u, _ := url.Parse(rr.Header().Get("Location"))
	q := u.Query()
	assert.Equal(t, "invalid scope", q.Get("error"))
	assert.Equal(t, "keep-me", q.Get("state"))
	assert.NotEmpty(t, q.Get("error_description"))
}

func TestAuthorization_InvalidResourceURL_302_ErrorRedirect(t *testing.T) {
	scope := "read"
	client := makeClient("c1", []string{"https://app.example.com/cb"}, &scope)
	mp := &mockProvider{store: makeStoreWithClient(client)}
	h := AuthorizationHandler(AuthorizationHandlerOptions{Provider: mp})

	qs := url.Values{
		"client_id":             {"c1"},
		"redirect_uri":          {"https://app.example.com/cb"},
		"response_type":         {"code"},
		"code_challenge":        {validChallenge},
		"code_challenge_method": {"S256"},
		"resource":              {"/relative"}, // 非绝对 URL
	}
	req := newGET("/authorize?" + qs.Encode())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusFound, rr.Code)
	u, _ := url.Parse(rr.Header().Get("Location"))
	q := u.Query()
	assert.Equal(t, "invalid request", q.Get("error"))
	assert.NotEmpty(t, q.Get("error_description"))
}

func TestAuthorization_RateLimit_429_JSON(t *testing.T) {
	client := makeClient("c1", []string{"https://app.example.com/cb"}, nil)
	mp := &mockProvider{store: makeStoreWithClient(client)}
	limiter := rate.NewLimiter(0, 0)

	h := AuthorizationHandler(AuthorizationHandlerOptions{
		Provider:  mp,
		RateLimit: limiter,
	})

	req := newGET("/authorize")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	var resp oauthErrResp
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, "too many requests", resp.Error)
}

func TestAllowedMethods_GET_and_POST(t *testing.T) {
	client := makeClient("c1", []string{"https://cb"}, nil)
	mp := &mockProvider{store: makeStoreWithClient(client)}
	h := AuthorizationHandler(AuthorizationHandlerOptions{Provider: mp})

	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, newGET("/authorize"))
	assert.NotEqual(t, http.StatusMethodNotAllowed, rr1.Code)

	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPut, "/authorize", nil)
	h.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusMethodNotAllowed, rr2.Code)
}

func TestHelpers_StateParsing_GET_and_POST(t *testing.T) {
	// GET
	reqGet := newGET("/authorize?state=GETSTATE")
	assert.Equal(t, "GETSTATE", getStateFromRequest(reqGet))

	// POST
	form := url.Values{"state": {"POSTSTATE"}}
	reqPost := newPOST("/authorize", form)
	assert.Equal(t, "POSTSTATE", getStateFromRequest(reqPost))
}

func TestHelpers_ParseParams_Parity(t *testing.T) {
	// ClientAuthorizationParams
	qs := url.Values{"client_id": {"c1"}, "redirect_uri": {"https://a/cb"}}
	cp := parseClientAuthorizationParams(newGET("/authorize?" + qs.Encode()))
	assert.Equal(t, "c1", cp.ClientID)
	assert.Equal(t, "https://a/cb", cp.RedirectURI)

	// RequestAuthorizationParams (POST)
	form := url.Values{
		"response_type":         {"code"},
		"code_challenge":        {"abc"},
		"code_challenge_method": {"S256"},
		"scope":                 {"read write"},
		"resource":              {"https://api.example.com"},
		"state":                 {"s1"},
	}
	rp := parseRequestAuthorizationParams(newPOST("/authorize", form))
	assert.Equal(t, "code", rp.ResponseType)
	assert.Equal(t, "abc", rp.CodeChallenge)
	assert.Equal(t, "S256", rp.CodeChallengeMethod)
	assert.Equal(t, "read write", rp.Scope)
	assert.Equal(t, "s1", rp.State)
	assert.Equal(t, "https://api.example.com", rp.Resource)
}

func TestCreateErrorRedirect_ComposesQuery(t *testing.T) {
	type inlineErr struct {
		ErrorCode string
		Message   string
		ErrorURI  string
	}
	errObj := inlineErr{ErrorCode: "invalid request", Message: "oops"}
	bs, _ := json.Marshal(errObj)
	var rehydrated struct {
		ErrorCode string
		Message   string
		ErrorURI  string
	}
	_ = json.Unmarshal(bs, &rehydrated)

	loc := createErrorRedirect("https://app.example.com/cb", rehydrated, "st")
	u, _ := url.Parse(loc)
	q := u.Query()
	assert.Equal(t, "invalid request", q.Get("error"))
	assert.Equal(t, "oops", q.Get("error_description"))
	assert.Equal(t, "st", q.Get("state"))
}
