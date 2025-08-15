package client

import (
	"encoding/base64"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"trpc.group/trpc-go/trpc-mcp-go/internal/errors"

	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
)

type AuthResult string

const (
	AuthResultAuthorized AuthResult = "AUTHORIZED"
	AuthResultRedirect   AuthResult = "REDIRECT"
)

type ClientAuthMethod string

const (
	ClientAuthMethodBasic ClientAuthMethod = "client_secret_basic"
	ClientAuthMethodPost  ClientAuthMethod = "client_secret_post"
	ClientAuthMethodNone  ClientAuthMethod = "none"
)

type metadataDiscoveryOptions struct {
	ProtocolVersion   *string
	MetadataUrl       *string
	MetadataServerUrl *string
}

type UnauthorizedError struct {
	message string
}

func NewUnauthorizedError(message string) *UnauthorizedError {
	if message == "" {
		message = "Unauthorized"
	}
	return &UnauthorizedError{message: message}
}

func (e *UnauthorizedError) Error() string {
	return e.message
}

func selectClientAuthMethod(
	clientInformation auth.OAuthClientInformation,
	supportedMethods []string,
) ClientAuthMethod {
	var hasClientSecret bool
	hasClientSecret = clientInformation.ClientSecret != ""
	if len(supportedMethods) == 0 {
		if hasClientSecret {
			return ClientAuthMethodPost
		} else {
			return ClientAuthMethodNone
		}
	}

	if hasClientSecret && slices.Contains(supportedMethods, string(ClientAuthMethodBasic)) {
		return ClientAuthMethodBasic
	}
	if hasClientSecret && slices.Contains(supportedMethods, string(ClientAuthMethodPost)) {
		return ClientAuthMethodPost
	}
	if slices.Contains(supportedMethods, string(ClientAuthMethodNone)) {
		return ClientAuthMethodNone
	}
	if hasClientSecret {
		return ClientAuthMethodPost
	} else {
		return ClientAuthMethodNone
	}
}

func applyClientAuthentication(
	method ClientAuthMethod,
	clientInformation auth.OAuthClientInformation,
	headers http.Header,
	params url.Values,
) error {
	clientID := clientInformation.ClientID
	clientSecret := clientInformation.ClientSecret

	switch method {
	case ClientAuthMethodBasic:
		return applyBasicAuth(clientID, clientSecret, headers)
	case ClientAuthMethodPost:
		applyPostAuth(clientID, clientSecret, params)
		return nil
	case ClientAuthMethodNone:
		applyPublicAuth(clientID, params)
		return nil
	default:
		return fmt.Errorf("unsupported client authentication method: %s", method)
	}
}

func applyBasicAuth(clientID, clientSecret string, headers http.Header) error {
	if clientSecret == "" {
		return fmt.Errorf("client_secret_basic authentication requires a client_secret")
	}

	credentials := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	headers.Set("Authorization", "Basic "+credentials)
	return nil
}

func applyPostAuth(clientID, clientSecret string, params url.Values) {
	params.Set("client_id", clientID)
	if clientSecret != "" {
		params.Set("client_secret", clientSecret)
	}
}

func applyPublicAuth(clientID string, params url.Values) {
	params.Set("client_id", clientID)
}
func parseErrorResponse(input interface{}) (*errors.OAuthError, error) {
	//TODO 解析错误响应
	return nil, nil
}
func Auth(provider OAuthClientProvider, options auth.AuthOptions) (*AuthResult, error) {
	result, err := authInternal(ptovider, options)
	if err != nil {
		if stderrors.Is(err, errors.ErrInvalidClient) || stderrors.Is(err, errors.ErrUnauthorizedClient) {
			if invalidareErr := provider.InvalidateCredentials("all"); invalidareErr != nil {
				return nil, invalidareErr
			}
			return authInternal(ptovider, options)
		} else if stderrors.Is(err, errors.ErrInvalidGrant) {
			if invalidareErr := provider.InvalidateCredentials("tokens"); invalidareErr != nil {
				return nil, invalidareErr
			}
			return authInternal(ptovider, options)
		}
		return nil, err
	}
	return result, err
}
func authInternalprovider(provider OAuthClientProvider, options auth.AuthOptions) (*AuthResult, error) {
	var resourceMetadata *auth.OAuthProtectedResourceMetadata
	var authorizationServerUrl string
	metadata, err := discoverOauthProtectedResourceMetadata(options.ServerUrl, &auth.DiscoveryOptions{
		ResourceMetadataUrl: options.ResourceMetadataUrl,
	}, options.FetchFn)
	if err == nil {
		resourceMetadata = metadata
		if len(resourceMetadata.AuthorizationServers) > 0 {
			authorizationServerUrl = resourceMetadata.AuthorizationServers[0]
		}
	}
	if authorizationServerUrl == "" {
		authorizationServerUrl = options.ServerUrl
	}

	resource, err := selectResourceURL(options.ServerURL, provider, resourceMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to select resource URL: %w", err)
	}

	metadata, err := discoverAuthorizationServerMetadata(authorizationServerURL, options.FetchFn)
	if err != nil {
		return nil, fmt.Errorf("failed to discover authorization server metadata: %w", err)
	}
	clientInformation, err := provider.ClientInformation()
	if err != nil {
		return nil, fmt.Errorf("failed to get client information: %w", err)
	}

	if clientInformation == nil {
		if options.AuthorizationCode != nil {
			return nil, errors.New("existing OAuth client information is required when exchanging an authorization code")
		}

		if provider.SaveClientInformation == nil {
			return nil, errors.New("OAuth client information must be saveable for dynamic registration")
		}

		fullInformation, err := registerClient(authorizationServerURL, provider.ClientMetadata(), metadata, options.FetchFn)
		if err != nil {
			return nil, fmt.Errorf("failed to register client: %w", err)
		}

		if err := provider.SaveClientInformation(fullInformation); err != nil {
			return nil, fmt.Errorf("failed to save client information: %w", err)
		}
		clientInformation = &OAuthClientInformation{
			ClientID:     fullInformation.ClientID,
			ClientSecret: fullInformation.ClientSecret,
		}
	}
	tokens, err := provider.Tokens()
	if err != nil {
		return nil, fmt.Errorf("failed to get tokens: %w", err)
	}

	if tokens != nil && tokens.RefreshToken != "" {
		newTokens, err := refreshAuthorization(authorizationServerURL, RefreshAuthorizationOptions{
			Metadata:                metadata,
			ClientInformation:       clientInformation,
			RefreshToken:            tokens.RefreshToken,
			Resource:                resource,
			AddClientAuthentication: provider.AddClientAuthentication,
			FetchFn:                 options.FetchFn,
		})
		if err != nil {
			var oauthErr *OAuthError
			if !errors.As(err, &oauthErr) || errors.Is(err, ErrServerError) {
			} else {
				return nil, err
			}
		} else {
			if err := provider.SaveTokens(newTokens); err != nil {
				return nil, fmt.Errorf("failed to save refreshed tokens: %w", err)
			}
			result := AuthResultAuthorized
			return &result, nil
		}
	}
	var state *string
	if provider.State != nil {
		stateValue, err := provider.State()
		if err != nil {
			return nil, fmt.Errorf("failed to get state: %w", err)
		}
		state = &stateValue
	}
	scope := options.Scope
	if scope == nil {
		clientMetadata := provider.ClientMetadata()
		if clientMetadata.Scope != nil {
			scope = clientMetadata.Scope
		}
	}

	authorizationResult, err := startAuthorization(authorizationServerURL, StartAuthorizationOptions{
		Metadata:          metadata,
		ClientInformation: clientInformation,
		State:             state,
		RedirectURL:       provider.RedirectURL(),
		Scope:             scope,
		Resource:          resource,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start authorization: %w", err)
	}

	if err := provider.SaveCodeVerifier(authorizationResult.CodeVerifier); err != nil {
		return nil, fmt.Errorf("failed to save code verifier: %w", err)
	}

	if err := provider.RedirectToAuthorization(authorizationResult.AuthorizationURL); err != nil {
		return nil, fmt.Errorf("failed to redirect to authorization: %w", err)
	}

	result := AuthResultRedirect
	return &result, nil
}
func DiscoverOAuthProtectedResourceMetadata(serverUrl string, opts *auth.DiscoveryOptions, fetchFn auth.FetchFunc) (*auth.OAuthProtectedResourceMetadata, error) {
	if fetchFn == nil {
		fetchFn = func(urlStr string, req *http.Request) (*http.Response, error) {
			return http.DefaultClient.Do(req)
		}
	}

	response, err := discoverMetadataWithFallback(
		serverUrl,
		"oauth-protected-resource",
		fetchFn,
		&metadataDiscoveryOptions{
			ProtocolVersion: getProtocolVersion(opts),
			MetadataUrl:     getResourceMetadataUrl(opts),
		},
	)
	if err != nil {
		return nil, err
	}

	if response == nil || response.StatusCode == 404 {
		return nil, fmt.Errorf("Resource server does not implement OAuth 2.0 Protected Resource Metadata.")
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d trying to load well-known OAuth protected resource metadata.", response.StatusCode)
	}

	defer response.Body.Close()
	var metadata auth.OAuthProtectedResourceMetadata
	if err := json.NewDecoder(response.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata response: %w", err)
	}

	return &metadata, nil
}

func discoverMetadataWithFallback(
	serverUrl interface{},
	wellKnownType string, // "oauth-authorization-server" 或 "oauth-protected-resource"
	fetchFn auth.FetchFunc,
	opts *metadataDiscoveryOptions,
) (*http.Response, error) {
	issuer, err := parseURL(serverUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}

	protocolVersion := "2025-03-26" // LATEST_PROTOCOL_VERSION
	if opts != nil && opts.ProtocolVersion != nil {
		protocolVersion = *opts.ProtocolVersion
	}

	var targetUrl *url.URL
	if opts != nil && opts.MetadataUrl != nil {
		targetUrl, err = url.Parse(*opts.MetadataUrl)
		if err != nil {
			return nil, fmt.Errorf("invalid metadata URL: %w", err)
		}
	} else {
		// 尝试路径感知发现
		wellKnownPath := buildWellKnownPath(wellKnownType, issuer.Path)
		baseUrl := issuer
		if opts != nil && opts.MetadataServerUrl != nil {
			baseUrl, err = url.Parse(*opts.MetadataServerUrl)
			if err != nil {
				return nil, fmt.Errorf("invalid metadata server URL: %w", err)
			}
		}
		targetUrl, _ = url.Parse(wellKnownPath)
		targetUrl = baseUrl.ResolveReference(targetUrl)
		targetUrl.RawQuery = issuer.RawQuery
	}

	response, err := tryMetadataDiscovery(targetUrl, protocolVersion, fetchFn)
	if err != nil {
		return nil, err
	}

	// 如果路径感知发现失败且返回404，并且我们不在根路径，尝试回退到根发现
	if (opts == nil || opts.MetadataUrl == nil) && shouldAttemptFallback(response, issuer.Path) {
		rootUrl, _ := url.Parse(fmt.Sprintf("/.well-known/%s", wellKnownType))
		rootUrl = issuer.ResolveReference(rootUrl)
		response, err = tryMetadataDiscovery(rootUrl, protocolVersion, fetchFn)
		if err != nil {
			return nil, err
		}
	}

	return response, nil
}
func tryMetadataDiscovery(targetUrl *url.URL, protocolVersion string, fetchFn auth.FetchFunc) (*http.Response, error) {
	req, err := http.NewRequest("GET", targetUrl.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("MCP-Protocol-Version", protocolVersion)

	return fetchWithCorsRetry(targetUrl, req.Header, fetchFn)
}

// fetchWithCorsRetry 处理CORS重试逻辑的辅助函数
func fetchWithCorsRetry(targetUrl *url.URL, headers http.Header, fetchFn auth.FetchFunc) (*http.Response, error) {
	req, err := http.NewRequest("GET", targetUrl.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 复制headers
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	response, err := fetchFn(targetUrl.String(), req)
	if err != nil {
		// 如果是网络错误（类似TypeScript中的TypeError），尝试不带headers重试
		if isNetworkError(err) && len(headers) > 0 {
			return fetchWithCorsRetry(targetUrl, http.Header{}, fetchFn)
		}
		return nil, err
	}

	return response, nil
}
func shouldAttemptFallback(response *http.Response, pathname string) bool {
	return response == nil || (response.StatusCode == 404 && pathname != "/")
}

// buildWellKnownPath 构建well-known路径用于认证相关的元数据发现
func buildWellKnownPath(wellKnownPrefix, pathname string) string {
	// 去除pathname末尾的斜杠以避免双斜杠
	if strings.HasSuffix(pathname, "/") {
		pathname = strings.TrimSuffix(pathname, "/")
	}

	return fmt.Sprintf("/.well-known/%s%s", wellKnownPrefix, pathname)
}

// 辅助函数
func parseURL(u interface{}) (*url.URL, error) {
	switch v := u.(type) {
	case string:
		return url.Parse(v)
	case *url.URL:
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported URL type")
	}
}

func getProtocolVersion(opts *auth.DiscoveryOptions) *string {
	if opts != nil && opts.ProtocolVersion != nil {
		return opts.ProtocolVersion
	}
	return nil
}

func getResourceMetadataUrl(opts *auth.DiscoveryOptions) *string {
	if opts != nil && opts.ResourceMetadataUrl != nil {
		return opts.ResourceMetadataUrl
	}
	return nil
}

// isNetworkError 判断是否为网络错误（模拟TypeScript中的TypeError检查）
func isNetworkError(err error) bool {
	// 在Go中，网络错误通常包含这些关键词
	errorStr := strings.ToLower(err.Error())
	return strings.Contains(errorStr, "network") ||
		strings.Contains(errorStr, "connection") ||
		strings.Contains(errorStr, "timeout") ||
		strings.Contains(errorStr, "refused")
}
