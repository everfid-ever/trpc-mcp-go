package server

import (
	"net/http"
	"net/url"

	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
)

type AuthorizationParams struct {
	CodeChallenge string   `json:"code_challenge"` // 必需
	RedirectURI   string   `json:"redirect_uri"`   // 必需
	State         string   `json:"state"`          //optional.An opaque value used by the client to maintain state between the request and callback.
	Scopes        []string `json:"scopes"`         // 可选，空切片表示未提供
	Resource      *url.URL `json:"resource"`       // 可选，nil表示未提供
}

// OAuthServerProvider 定义了一个完整的OAuth 2.1服务器接口，包含客户端管理、授权流程、令牌交换、验证和撤销等功能。
// defines a complete OAuth 2.1 server interface, including client management, authorization flow, token exchange, verification, and revocation.
type OAuthServerProvider interface {

	// ClientsStore getter函数:返回用于读取注册OAuth客户端信息的存储。
	// A store used to read information about registered OAuth clients.
	ClientsStore() *OAuthClientsStore

	// Authorize 启动授权流程，可以由服务器自身实现或通过重定向到独立的授权服务器。
	// AuthorizationFlow的入口点，由服务器实现。
	// 服务器最终必须通过给定的重定向URI发出带有授权响应或错误响应的重定向。根据OAuth 2.1规范：
	// - 成功情况下，重定向必须包含 `code` 和 `state`（如果提供）查询参数。
	// - 错误情况下，重定向必须包含 `error` 查询参数，并可以包含可选的 `error_description` 查询参数。
	// Begins the authorization flow, which can either be implemented by this server itself or via redirection to a separate authorization server.
	// This server must eventually issue a redirect with an authorization response or an error response to the given redirect URI. Per OAuth 2.1:
	// - In the successful case, the redirect MUST include the `code` and `state` (if present) query parameters.
	// - In the error case, the redirect MUST include the `error` query parameter, and MAY include an optional `error_description` query parameter.
	Authorize(client auth.OAuthClientInformationFull, params AuthorizationParams, res http.ResponseWriter, req *http.Request) error

	// ChallengeForAuthorizationCode 返回指定授权开始时使用的 codeChallenge 值。
	// Returns the `codeChallenge` that was used when the indicated authorization began.
	ChallengeForAuthorizationCode(client auth.OAuthClientInformationFull, authorizationCode string) (string, error)

	// ExchangeAuthorizationCode 将授权码交换为访问令牌。
	// Exchanges an authorization code for an access token.
	ExchangeAuthorizationCode(
		client auth.OAuthClientInformationFull,
		authorizationCode string, codeVerifier *string,
		redirectUri *string,
		resource *url.URL,
	) (*auth.OAuthTokens, error)

	// ExchangeRefreshToken 用刷新令牌交换新的访问令牌。
	// Exchanges a refresh token for an access token.
	ExchangeRefreshToken(
		client auth.OAuthClientInformationFull,
		refreshToken string,
		scopes []string, // 可选，若为空表示未提供 / Optional, empty slice if not provided
		resource *url.URL, // 可选，若为nil表示未提供 / Optional, nil if not provided
	) (*auth.OAuthTokens, error)

	// VerifyAccessToken 验证访问令牌并返回其相关信息。
	// Verifies an access token and returns information about it.
	VerifyAccessToken(token string) (*AuthInfo, error)

	// SupportTokenRevocation 是否支持令牌撤销。（可选）
	SupportTokenRevocation
}

type SupportTokenRevocation interface {
	// RevokeToken 撤销访问令牌或刷新令牌。如果未实现，则不支持令牌撤销（不推荐）。
	// 如果给定的令牌无效或已被撤销，此方法应不执行任何操作。
	// Revokes an access or refresh token. If unimplemented, token revocation is not supported (not recommended).
	// If the given token is invalid or already revoked, this method should do nothing.
	// 可选方法 / Optional method
	RevokeToken(client auth.OAuthClientInformationFull, request auth.OAuthTokenRevocationRequest) error
}

type TokenVerifier interface {
	VerifyAccessToken(token string) (*AuthInfo, error)
	VerifyRefreshToken(token string) (*AuthInfo, error)
}
