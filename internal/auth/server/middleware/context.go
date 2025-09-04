package middleware

// authInfoKeyType 用于在上下文中存储和检索 AuthInfo 的键类型
type authInfoKeyType struct{}

// AuthInfoKey 是用于存储 AuthInfo 的上下文键
var AuthInfoKey = authInfoKeyType{}
