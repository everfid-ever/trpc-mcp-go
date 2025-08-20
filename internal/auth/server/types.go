package server

import "net/url"

// AuthInfo 包含有关已验证访问令牌的信息，提供给请求处理程序。
type AuthInfo struct {
	// Token 是访问令牌。
	Token string `json:"token"`

	// ClientID 是与此令牌关联的客户端ID。
	ClientID string `json:"clientId"`

	// Scopes 是与此令牌关联的权限范围。
	Scopes []string `json:"scopes"`

	// ExpiresAt 是令牌的过期时间（自Unix纪元以来的秒数）。
	// 如果为nil，表示未提供过期时间。
	ExpiresAt *int64 `json:"expiresAt,omitempty"`

	// Resource 是RFC 8707资源服务器标识符，表示此令牌有效的资源。
	// 如果设置，必须与MCP服务器的资源标识符匹配（不包括哈希片段）。
	// 如果为nil，表示未提供。
	Resource *url.URL `json:"resource,omitempty"`

	// Extra 是与令牌关联的额外数据。
	// 此字段用于附加任何需要附着在认证信息上的额外数据。
	// 如果为nil，表示未提供额外数据。
	Extra map[string]interface{} `json:"extra,omitempty"`
}
