package middleware

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
)

// AuditLevel 定义审计日志级别
type AuditLevel int

const (
	AuditLevelNone AuditLevel = iota
	AuditLevelBasic
	AuditLevelDetailed
	AuditLevelFull
)

// AuditEvent 表示 OAuth2.1 操作的审计事件
type AuditEvent struct {
	EventID      string                 `json:"event_id"`
	Timestamp    time.Time              `json:"timestamp"`
	EventType    string                 `json:"event_type"`
	AuditLevel   AuditLevel             `json:"audit_level"`
	Method       string                 `json:"method"`
	Path         string                 `json:"path"`
	QueryParams  map[string]string      `json:"query_params,omitempty"`
	Headers      map[string]string      `json:"headers,omitempty"`
	RemoteAddr   string                 `json:"remote_addr"`
	UserAgent    string                 `json:"user_agent"`
	RequestID    string                 `json:"request_id,omitempty"`
	ClientID     string                 `json:"client_id,omitempty"`
	Subject      string                 `json:"subject,omitempty"`
	Scopes       []string               `json:"scopes,omitempty"`
	GrantType    string                 `json:"grant_type,omitempty"`
	ResponseType string                 `json:"response_type,omitempty"`
	RedirectURI  string                 `json:"redirect_uri,omitempty"`
	Resource     string                 `json:"resource,omitempty"`
	StatusCode   int                    `json:"status_code"`
	ResponseTime time.Duration          `json:"response_time"`
	ErrorCode    string                 `json:"error_code,omitempty"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	TokenHash    string                 `json:"token_hash,omitempty"`
	CodeHash     string                 `json:"code_hash,omitempty"`
	IPHash       string                 `json:"ip_hash,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	RiskLevel    string                 `json:"risk_level,omitempty"`
	RiskFactors  []string               `json:"risk_factors,omitempty"`
	RequestBody  string                 `json:"request_body,omitempty"`
	ResponseBody string                 `json:"response_body,omitempty"`
}

// AuditLogger 定义审计日志接口
type AuditLogger interface {
	LogEvent(event AuditEvent) error
	LogError(event AuditEvent, err error) error
}

// DefaultAuditLogger 使用 zap 实现审计日志
type DefaultAuditLogger struct {
	logger *zap.Logger
}

// NewAuditLogger 创建审计日志器，支持默认或自定义 zap logger
func NewAuditLogger(logger *zap.Logger) *DefaultAuditLogger {
	if logger == nil {
		var err error
		logger, err = zap.NewProduction()
		if err != nil {
			logger, _ = zap.NewDevelopment()
		}
	}
	return &DefaultAuditLogger{logger: logger}
}

// GetZapLogger 返回底层 zap logger
func (l *DefaultAuditLogger) GetZapLogger() *zap.Logger {
	return l.logger
}

// LogEvent 记录审计事件
func (l *DefaultAuditLogger) LogEvent(event AuditEvent) error {
	if l.logger == nil {
		return fmt.Errorf("zap logger not initialized")
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	l.logger.Info("[AUDIT]",
		zap.ByteString("event", data),
		zap.Any("audit", struct {
			Method       string
			Path         string
			StatusCode   int
			ResponseTime time.Duration
			ClientID     string
			Subject      string
			Scopes       []string
			RiskLevel    string
		}{
			Method:       event.Method,
			Path:         event.Path,
			StatusCode:   event.StatusCode,
			ResponseTime: event.ResponseTime,
			ClientID:     event.ClientID,
			Subject:      event.Subject,
			Scopes:       event.Scopes,
			RiskLevel:    event.RiskLevel,
		}),
	)
	return nil
}

// LogError 记录带有错误的审计事件
func (l *DefaultAuditLogger) LogError(event AuditEvent, err error) error {
	event.ErrorMessage = err.Error()
	return l.LogEvent(event)
}

// AuditMiddlewareOptions 定义审计中间件配置
type AuditMiddlewareOptions struct {
	Logger              AuditLogger
	Level               AuditLevel
	HashSensitiveData   bool
	IncludeRequestBody  bool
	IncludeResponseBody bool
	RiskAssessor        func(AuditEvent) (string, []string)
	MetadataExtractor   func(*http.Request) map[string]interface{}
	EndpointPatterns    []string
	ExcludePatterns     []string
	SensitiveKeys       []string
}

// DefaultAuditMiddlewareOptions 返回默认审计配置
func DefaultAuditMiddlewareOptions() *AuditMiddlewareOptions {
	return &AuditMiddlewareOptions{
		Logger:            NewAuditLogger(nil),
		Level:             AuditLevelDetailed,
		HashSensitiveData: true,
		EndpointPatterns: []string{
			"/oauth2/authorize",
			"/oauth2/token",
			"/oauth2/revoke",
			"/oauth2/register",
			"/oauth2/metadata",
		},
		SensitiveKeys: []string{"client_secret", "code_verifier", "password", "authorization", "cookie", "x-api-key"},
	}
}

// AuditOptionsBuilder 用于构建审计中间件选项
type AuditOptionsBuilder struct {
	options *AuditMiddlewareOptions
}

// NewAuditOptionsBuilder 创建配置构建器
func NewAuditOptionsBuilder() *AuditOptionsBuilder {
	return &AuditOptionsBuilder{options: DefaultAuditMiddlewareOptions()}
}

// WithLogger 设置自定义 logger
func (b *AuditOptionsBuilder) WithLogger(logger *zap.Logger) *AuditOptionsBuilder {
	b.options.Logger = NewAuditLogger(logger)
	return b
}

// WithLevel 设置审计级别
func (b *AuditOptionsBuilder) WithLevel(level AuditLevel) *AuditOptionsBuilder {
	b.options.Level = level
	return b
}

// WithHashSensitiveData 设置是否哈希敏感数据
func (b *AuditOptionsBuilder) WithHashSensitiveData(hash bool) *AuditOptionsBuilder {
	b.options.HashSensitiveData = hash
	return b
}

// WithRequestBody 设置是否包含请求体
func (b *AuditOptionsBuilder) WithRequestBody(include bool) *AuditOptionsBuilder {
	b.options.IncludeRequestBody = include
	return b
}

// WithResponseBody 设置是否包含响应体
func (b *AuditOptionsBuilder) WithResponseBody(include bool) *AuditOptionsBuilder {
	b.options.IncludeResponseBody = include
	return b
}

// WithRiskAssessor 设置风险评估函数
func (b *AuditOptionsBuilder) WithRiskAssessor(assessor func(AuditEvent) (string, []string)) *AuditOptionsBuilder {
	b.options.RiskAssessor = assessor
	return b
}

// WithMetadataExtractor 设置元数据提取函数
func (b *AuditOptionsBuilder) WithMetadataExtractor(extractor func(*http.Request) map[string]interface{}) *AuditOptionsBuilder {
	b.options.MetadataExtractor = extractor
	return b
}

// WithEndpointPatterns 设置审计端点模式
func (b *AuditOptionsBuilder) WithEndpointPatterns(patterns []string) *AuditOptionsBuilder {
	b.options.EndpointPatterns = patterns
	return b
}

// WithExcludePatterns 设置排除模式
func (b *AuditOptionsBuilder) WithExcludePatterns(patterns []string) *AuditOptionsBuilder {
	b.options.ExcludePatterns = patterns
	return b
}

// WithSensitiveKeys 设置敏感字段
func (b *AuditOptionsBuilder) WithSensitiveKeys(keys []string) *AuditOptionsBuilder {
	b.options.SensitiveKeys = keys
	return b
}

// Build 返回最终配置
func (b *AuditOptionsBuilder) Build() *AuditMiddlewareOptions {
	return b.options
}

// AuditMiddleware 创建审计中间件
func AuditMiddleware(options *AuditMiddlewareOptions) func(http.Handler) http.Handler {
	if options == nil {
		options = DefaultAuditMiddlewareOptions()
	}
	if options.Logger == nil {
		options.Logger = NewAuditLogger(nil)
	}
	if err := validateOptions(options); err != nil {
		panic(fmt.Sprintf("invalid audit middleware options: %v", err))
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !shouldAuditPath(r.URL.Path, options.EndpointPatterns, options.ExcludePatterns) {
				next.ServeHTTP(w, r)
				return
			}
			// Check if it is an SSE request
			acceptHeader := r.Header.Get("Accept")
			isSSE := strings.Contains(acceptHeader, "text/event-stream")

			event, wrappedWriter := initializeAuditEvent(w, r, options)

			// For SSE requests, the response body is not captured to avoid interfering with streaming.
			if isSSE {
				wrappedWriter.captured = false
			}
			defer logAuditEvent(event, wrappedWriter, options)
			next.ServeHTTP(wrappedWriter, r)
		})
	}
}

// validateOptions 验证配置
func validateOptions(options *AuditMiddlewareOptions) error {
	if len(options.EndpointPatterns) == 0 && len(options.ExcludePatterns) == 0 {
		return fmt.Errorf("at least one endpoint pattern or exclude pattern must be specified")
	}
	return nil
}

// auditResponseWriter 包装 ResponseWriter 以捕获状态码和响应体
type auditResponseWriter struct {
	http.ResponseWriter
	statusCode int
	body       []byte
	captured   bool
}

func (w *auditResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *auditResponseWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	if w.captured {
		w.body = append(w.body, b...)
	}
	return w.ResponseWriter.Write(b)
}

func (w *auditResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Unwrap 返回底层的 ResponseWriter
func (w *auditResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// OAuthInfo 包含从请求中提取的 OAuth2.1 信息
type OAuthInfo struct {
	ClientID     string
	Subject      string
	Scopes       []string
	GrantType    string
	ResponseType string
	RedirectURI  string
	Resource     string
	Token        string
	Code         string
}

// extractOAuthInfo 提取 OAuth2.1 特定信息
func extractOAuthInfo(r *http.Request) OAuthInfo {
	info := OAuthInfo{}
	if r.URL != nil {
		query := r.URL.Query()
		info.ClientID = query.Get("client_id")
		info.ResponseType = query.Get("response_type")
		info.RedirectURI = query.Get("redirect_uri")
		info.Resource = query.Get("resource")
		if scope := query.Get("scope"); scope != "" {
			info.Scopes = strings.Split(scope, " ")
		}
	}
	if err := r.ParseForm(); err == nil {
		if info.GrantType == "" {
			info.GrantType = r.FormValue("grant_type")
		}
		info.Code = r.FormValue("code")
		if scope := r.FormValue("scope"); scope != "" && len(info.Scopes) == 0 {
			info.Scopes = strings.Split(scope, " ")
		}
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		info.Token = strings.TrimPrefix(auth, "Bearer ")
	}
	if authInfo, ok := GetAuthInfo(r.Context()); ok {
		info.Subject = extractSubject(authInfo)
		if len(info.Scopes) == 0 {
			info.Scopes = authInfo.Scopes
		}
		if cid, ok := authInfo.Extra["client_id"].(string); ok && info.ClientID == "" {
			info.ClientID = cid
		}
		// 兜底：有的 Verifier 会直接把 client_id 放到 AuthInfo.ClientID
		if info.ClientID == "" && authInfo.ClientID != "" {
			info.ClientID = authInfo.ClientID
		}
	}
	return info
}

// shouldAuditPath 判断路径是否需要审计
func shouldAuditPath(path string, includePatterns, excludePatterns []string) bool {
	for _, pattern := range excludePatterns {
		if matched, _ := regexp.MatchString(pattern, path); matched {
			return false
		}
	}
	if len(includePatterns) == 0 {
		return true
	}
	for _, pattern := range includePatterns {
		if matched, _ := regexp.MatchString(pattern, path); matched {
			return true
		}
	}
	return false
}

// determineEventType 确定事件类型
func determineEventType(path, method string) string {
	switch {
	case strings.Contains(path, "/authorize"):
		return "oauth_authorization"
	case strings.Contains(path, "/token"):
		return "oauth_token"
	case strings.Contains(path, "/revoke"):
		return "oauth_revocation"
	case strings.Contains(path, "/register"):
		return "oauth_registration"
	case strings.Contains(path, "/metadata"):
		return "oauth_metadata"
	default:
		return "oauth_request"
	}
}

// generateEventID 生成唯一事件 ID
func generateEventID() string {
	return fmt.Sprintf("audit_%d_%s", time.Now().UnixNano(), randomString(8))
}

// randomString 生成随机字符串
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		for i := range b {
			b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
		}
	} else {
		for i := range b {
			b[i] = charset[int(b[i])%len(charset)]
		}
	}
	return string(b)
}

// sanitizeMap 清理敏感键值对
func sanitizeMap[T string | []string](data map[string]T, sensitiveKeys []string) map[string]string {
	sanitized := make(map[string]string)
	for key, value := range data {
		isSensitive := false
		for _, sensitiveKey := range sensitiveKeys {
			if strings.EqualFold(key, sensitiveKey) {
				isSensitive = true
				break
			}
		}
		if isSensitive {
			sanitized[key] = "[REDACTED]"
		} else {
			switch v := any(value).(type) {
			case string:
				sanitized[key] = v
			case []string:
				if len(v) > 0 {
					sanitized[key] = v[0]
				}
			}
		}
	}
	return sanitized
}

// sanitizeQueryParams 清理查询参数
func sanitizeQueryParams(query map[string][]string, sensitiveKeys []string) map[string]string {
	return sanitizeMap(query, sensitiveKeys)
}

// sanitizeHeaders 清理头部信息
func sanitizeHeaders(headers map[string][]string, sensitiveKeys []string) map[string]string {
	return sanitizeMap(headers, sensitiveKeys)
}

// hashSensitiveData 创建敏感数据的 SHA256 哈希
func hashSensitiveData(data string) string {
	if data == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// defaultRiskAssessment 默认风险评估逻辑
func defaultRiskAssessment(event AuditEvent) (string, []string) {
	var riskFactors []string
	riskLevel := "low"
	if event.StatusCode >= 400 {
		riskFactors = append(riskFactors, "client_error")
	}
	if event.StatusCode >= 500 {
		riskFactors = append(riskFactors, "server_error")
		riskLevel = "medium"
	}
	if event.ResponseTime > 5*time.Second {
		riskFactors = append(riskFactors, "slow_response")
		riskLevel = "medium"
	}
	if event.ClientID == "" {
		riskFactors = append(riskFactors, "missing_client_id")
		riskLevel = "high"
	}
	if strings.Contains(event.Path, "/revoke") {
		riskFactors = append(riskFactors, "token_revocation")
		riskLevel = "medium"
	}
	if strings.Contains(event.Path, "/register") {
		riskFactors = append(riskFactors, "client_registration")
		riskLevel = "medium"
	}
	return riskLevel, riskFactors
}

// determineErrorCode 确定错误代码
func determineErrorCode(statusCode int) string {
	switch {
	case statusCode == 400:
		return "invalid_request"
	case statusCode == 401:
		return "invalid_token"
	case statusCode == 403:
		return "insufficient_scope"
	case statusCode == 404:
		return "not_found"
	case statusCode == 429:
		return "too_many_requests"
	case statusCode >= 500:
		return "server_error"
	default:
		return "unknown_error"
	}
}

// determineErrorMessage 从响应体提取错误信息
func determineErrorMessage(statusCode int, body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var errorResponse struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &errorResponse); err == nil {
		if errorResponse.ErrorDescription != "" {
			return errorResponse.ErrorDescription
		}
		if errorResponse.Error != "" {
			return errorResponse.Error
		}
	}
	return http.StatusText(statusCode)
}

// extractSubject 从 AuthInfo 提取 subject
func extractSubject(authInfo server.AuthInfo) string {
	if authInfo.Extra != nil {
		if sub, ok := authInfo.Extra["sub"].(string); ok {
			return sub
		}
	}
	return ""
}

// GetAuthInfo 从请求上下文中提取 AuthInfo
func GetAuthInfo(ctx context.Context) (server.AuthInfo, bool) {
	if authInfo, ok := ctx.Value(AuthInfoKey).(server.AuthInfo); ok {
		return authInfo, true
	}
	return server.AuthInfo{}, false
}

// initializeAuditEvent 初始化审计事件
func initializeAuditEvent(w http.ResponseWriter, r *http.Request, options *AuditMiddlewareOptions) (AuditEvent, *auditResponseWriter) {
	start := time.Now()

	// Read and reset the request body
	var reqBody []byte
	if (options.Level >= AuditLevelFull || options.IncludeRequestBody) && r.Body != nil {
		reqBody, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewBuffer(reqBody))
	}

	// Determines whether to capture the response body according to the configuration
	wrappedWriter := &auditResponseWriter{
		ResponseWriter: w,
		captured:       (options.Level >= AuditLevelFull || options.IncludeRequestBody),
	}
	oauthInfo := extractOAuthInfo(r)

	event := AuditEvent{
		EventID:      generateEventID(),
		Timestamp:    start,
		EventType:    determineEventType(r.URL.Path, r.Method),
		AuditLevel:   options.Level,
		Method:       r.Method,
		Path:         r.URL.Path,
		RemoteAddr:   r.RemoteAddr,
		UserAgent:    r.UserAgent(),
		RequestID:    r.Header.Get("X-Request-ID"),
		ClientID:     oauthInfo.ClientID,
		Subject:      oauthInfo.Subject,
		Scopes:       oauthInfo.Scopes,
		GrantType:    oauthInfo.GrantType,
		ResponseType: oauthInfo.ResponseType,
		RedirectURI:  oauthInfo.RedirectURI,
		Resource:     oauthInfo.Resource,
		Metadata:     make(map[string]interface{}),
	}

	if options.Level >= AuditLevelDetailed {
		event.QueryParams = sanitizeQueryParams(r.URL.Query(), options.SensitiveKeys)
		event.Headers = sanitizeHeaders(r.Header, options.SensitiveKeys)
	}

	if options.HashSensitiveData {
		event.TokenHash = hashSensitiveData(oauthInfo.Token)
		event.CodeHash = hashSensitiveData(oauthInfo.Code)
		event.IPHash = hashSensitiveData(r.RemoteAddr)
	}

	// If request body logging is enabled, write
	if (options.Level >= AuditLevelFull || options.IncludeRequestBody) && len(reqBody) > 0 {
		event.RequestBody = string(reqBody)
	}

	if options.MetadataExtractor != nil {
		event.Metadata = options.MetadataExtractor(r)
	}

	if options.RiskAssessor != nil {
		event.RiskLevel, event.RiskFactors = options.RiskAssessor(event)
	} else {
		event.RiskLevel, event.RiskFactors = defaultRiskAssessment(event)
	}

	return event, wrappedWriter
}

// logAuditEvent 记录审计事件
func logAuditEvent(event AuditEvent, w *auditResponseWriter, options *AuditMiddlewareOptions) {
	event.ResponseTime = time.Since(event.Timestamp)
	event.StatusCode = w.statusCode

	// To log the response body
	if w.captured && len(w.body) > 0 && (options.Level >= AuditLevelFull || options.IncludeResponseBody) {
		event.ResponseBody = string(w.body)
	}

	if event.StatusCode >= 400 {
		event.ErrorCode = determineErrorCode(event.StatusCode)
		event.ErrorMessage = determineErrorMessage(event.StatusCode, w.body)
	}

	if err := options.Logger.LogEvent(event); err != nil {
		fmt.Printf("[AUDIT ERROR] Failed to log audit event: %v\n", err)
	}
}

// WithOAuthAudit 创建 OAuth2.1 特定审计中间件
func WithOAuthAudit(options *AuditMiddlewareOptions) func(http.Handler) http.Handler {
	return AuditMiddleware(options)
}

// WithBasicAudit 创建基础审计中间件
func WithBasicAudit() func(http.Handler) http.Handler {
	return AuditMiddleware(NewAuditOptionsBuilder().
		WithLevel(AuditLevelBasic).
		Build())
}

// WithDetailedAudit 创建详细审计中间件
func WithDetailedAudit() func(http.Handler) http.Handler {
	return AuditMiddleware(NewAuditOptionsBuilder().
		WithLevel(AuditLevelDetailed).
		Build())
}

// WithFullAudit 创建完整审计中间件
func WithFullAudit() func(http.Handler) http.Handler {
	return AuditMiddleware(NewAuditOptionsBuilder().
		WithLevel(AuditLevelFull).
		WithRequestBody(true).
		WithResponseBody(true).
		Build())
}

// WithZapLogger 创建带自定义 zap logger 的审计配置
func WithZapLogger(logger *zap.Logger) *AuditMiddlewareOptions {
	return NewAuditOptionsBuilder().
		WithLogger(logger).
		Build()
}

// WithCustomZapLogger 创建带自定义 zap logger 和配置的审计配置
func WithCustomZapLogger(logger *zap.Logger, level AuditLevel, hashSensitive bool) *AuditMiddlewareOptions {
	return NewAuditOptionsBuilder().
		WithLogger(logger).
		WithLevel(level).
		WithHashSensitiveData(hashSensitive).
		Build()
}
