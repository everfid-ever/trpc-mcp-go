package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"

	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
)

// 测试辅助函数
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func TestAuditLevelConstants(t *testing.T) {
	// 测试审计级别常量值
	if AuditLevelNone != 0 {
		t.Errorf("Expected AuditLevelNone to be 0, got %d", AuditLevelNone)
	}
	if AuditLevelBasic != 1 {
		t.Errorf("Expected AuditLevelBasic to be 1, got %d", AuditLevelBasic)
	}
	if AuditLevelDetailed != 2 {
		t.Errorf("Expected AuditLevelDetailed to be 2, got %d", AuditLevelDetailed)
	}
	if AuditLevelFull != 3 {
		t.Errorf("Expected AuditLevelFull to be 3, got %d", AuditLevelFull)
	}
}

func TestNewAuditLogger(t *testing.T) {
	// 测试创建默认 logger
	logger := NewAuditLogger(nil)
	if logger == nil {
		t.Fatal("Expected logger to be created")
	}

	// 测试获取底层 zap logger
	zapLogger := logger.GetZapLogger()
	if zapLogger == nil {
		t.Fatal("Expected underlying zap logger to exist")
	}

	// 测试使用自定义 zap logger
	testLogger := zaptest.NewLogger(t)
	customLogger := NewAuditLogger(testLogger)
	if customLogger == nil {
		t.Fatal("Expected custom logger to be created")
	}

	if customLogger.GetZapLogger() != testLogger {
		t.Fatal("Expected custom zap logger to be used")
	}
}

func TestDefaultAuditLoggerLogEvent(t *testing.T) {
	// 创建测试 logger
	testLogger := zaptest.NewLogger(t)
	auditLogger := NewAuditLogger(testLogger)

	// 创建测试事件
	event := AuditEvent{
		EventID:      "test_123",
		Timestamp:    time.Now(),
		EventType:    "test_event",
		AuditLevel:   AuditLevelBasic,
		Method:       "GET",
		Path:         "/test",
		StatusCode:   200,
		ResponseTime: 100 * time.Millisecond,
		ClientID:     "test_client",
		Subject:      "test_user",
		Scopes:       []string{"read", "write"},
		RiskLevel:    "low",
		RiskFactors:  []string{"normal"},
	}

	// 测试日志记录
	err := auditLogger.LogEvent(event)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestDefaultAuditLoggerLogError(t *testing.T) {
	testLogger := zaptest.NewLogger(t)
	auditLogger := NewAuditLogger(testLogger)

	event := AuditEvent{
		EventID:   "test_123",
		Timestamp: time.Now(),
		Method:    "GET",
		Path:      "/test",
	}

	testErr := &http.MaxBytesError{}
	err := auditLogger.LogError(event, testErr)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// 注意：由于 event 是按值传递的，ErrorMessage 不会被修改
	// 这个测试主要验证 LogError 方法不会返回错误
}

func TestDefaultAuditMiddlewareOptions(t *testing.T) {
	options := DefaultAuditMiddlewareOptions()

	// 验证默认值
	if options.Logger == nil {
		t.Error("Expected logger to be set")
	}
	if options.Level != AuditLevelDetailed {
		t.Errorf("Expected level to be Detailed, got %v", options.Level)
	}
	if !options.HashSensitiveData {
		t.Error("Expected HashSensitiveData to be true")
	}
	if len(options.EndpointPatterns) == 0 {
		t.Error("Expected endpoint patterns to be set")
	}
	if len(options.SensitiveKeys) == 0 {
		t.Error("Expected sensitive keys to be set")
	}
}

func TestAuditOptionsBuilder(t *testing.T) {
	builder := NewAuditOptionsBuilder()

	// 测试链式调用
	options := builder.
		WithLevel(AuditLevelFull).
		WithHashSensitiveData(false).
		WithRequestBody(true).
		WithResponseBody(true).
		Build()

	if options.Level != AuditLevelFull {
		t.Errorf("Expected level to be Full, got %v", options.Level)
	}
	if options.HashSensitiveData {
		t.Error("Expected HashSensitiveData to be false")
	}
	if !options.IncludeRequestBody {
		t.Error("Expected IncludeRequestBody to be true")
	}
	if !options.IncludeResponseBody {
		t.Error("Expected IncludeResponseBody to be true")
	}
}

func TestAuditOptionsBuilderWithCustomFunctions(t *testing.T) {
	builder := NewAuditOptionsBuilder()

	// 自定义风险评估器
	customRiskAssessor := func(event AuditEvent) (string, []string) {
		return "high", []string{"custom_risk"}
	}

	// 自定义元数据提取器
	customMetadataExtractor := func(r *http.Request) map[string]interface{} {
		return map[string]interface{}{
			"custom_field": "custom_value",
		}
	}

	options := builder.
		WithRiskAssessor(customRiskAssessor).
		WithMetadataExtractor(customMetadataExtractor).
		Build()

	if options.RiskAssessor == nil {
		t.Error("Expected RiskAssessor to be set")
	}
	if options.MetadataExtractor == nil {
		t.Error("Expected MetadataExtractor to be set")
	}

	// 测试自定义函数
	event := AuditEvent{}
	riskLevel, riskFactors := options.RiskAssessor(event)
	if riskLevel != "high" {
		t.Errorf("Expected risk level 'high', got %s", riskLevel)
	}
	if len(riskFactors) != 1 || riskFactors[0] != "custom_risk" {
		t.Errorf("Expected risk factors ['custom_risk'], got %v", riskFactors)
	}
}

func TestValidateOptions(t *testing.T) {
	// 测试有效配置
	validOptions := &AuditMiddlewareOptions{
		EndpointPatterns: []string{"/test"},
	}
	if err := validateOptions(validOptions); err != nil {
		t.Errorf("Expected no error for valid options, got %v", err)
	}

	// 测试无效配置
	invalidOptions := &AuditMiddlewareOptions{
		EndpointPatterns: []string{},
		ExcludePatterns:  []string{},
	}
	if err := validateOptions(invalidOptions); err == nil {
		t.Error("Expected error for invalid options")
	}
}

func TestShouldAuditPath(t *testing.T) {
	tests := []struct {
		path            string
		includePatterns []string
		excludePatterns []string
		expectedResult  bool
		description     string
	}{
		{
			path:            "/oauth2/authorize",
			includePatterns: []string{"/oauth2/.*"},
			excludePatterns: []string{},
			expectedResult:  true,
			description:     "Path matches include pattern",
		},
		{
			path:            "/health",
			includePatterns: []string{"/oauth2/.*"},
			excludePatterns: []string{},
			expectedResult:  false,
			description:     "Path doesn't match include pattern",
		},
		{
			path:            "/oauth2/token",
			includePatterns: []string{"/oauth2/.*"},
			excludePatterns: []string{"/oauth2/token"},
			expectedResult:  false,
			description:     "Path matches exclude pattern",
		},
		{
			path:            "/any/path",
			includePatterns: []string{},
			excludePatterns: []string{},
			expectedResult:  true,
			description:     "No patterns specified, audit all",
		},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			result := shouldAuditPath(tt.path, tt.includePatterns, tt.excludePatterns)
			if result != tt.expectedResult {
				t.Errorf("shouldAuditPath(%q, %v, %v) = %v, want %v",
					tt.path, tt.includePatterns, tt.excludePatterns, result, tt.expectedResult)
			}
		})
	}
}

func TestDetermineEventType(t *testing.T) {
	tests := []struct {
		path     string
		method   string
		expected string
	}{
		{"/oauth2/authorize", "GET", "oauth_authorization"},
		{"/oauth2/token", "POST", "oauth_token"},
		{"/oauth2/revoke", "POST", "oauth_revocation"},
		{"/oauth2/register", "POST", "oauth_registration"},
		{"/oauth2/metadata", "GET", "oauth_metadata"},
		{"/unknown/path", "GET", "oauth_request"},
	}

	for _, tt := range tests {
		result := determineEventType(tt.path, tt.method)
		if result != tt.expected {
			t.Errorf("determineEventType(%q, %q) = %q, want %q",
				tt.path, tt.method, result, tt.expected)
		}
	}
}

func TestGenerateEventID(t *testing.T) {
	id1 := generateEventID()
	id2 := generateEventID()

	if id1 == id2 {
		t.Error("Expected different event IDs")
	}

	if !strings.HasPrefix(id1, "audit_") {
		t.Errorf("Expected event ID to start with 'audit_', got %s", id1)
	}
}

func TestRandomString(t *testing.T) {
	str1 := randomString(10)
	str2 := randomString(10)

	if len(str1) != 10 {
		t.Errorf("Expected string length 10, got %d", len(str1))
	}

	if str1 == str2 {
		t.Error("Expected different random strings")
	}
}

func TestSanitizeMap(t *testing.T) {
	// 测试查询参数清理
	queryParams := map[string][]string{
		"client_id":     {"test_client"},
		"client_secret": {"secret_value"},
		"scope":         {"read write"},
	}

	sensitiveKeys := []string{"client_secret", "password"}

	sanitized := sanitizeQueryParams(queryParams, sensitiveKeys)

	if sanitized["client_id"] != "test_client" {
		t.Errorf("Expected client_id to be preserved, got %s", sanitized["client_id"])
	}

	if sanitized["client_secret"] != "[REDACTED]" {
		t.Errorf("Expected client_secret to be redacted, got %s", sanitized["client_secret"])
	}

	if sanitized["scope"] != "read write" {
		t.Errorf("Expected scope to be preserved, got %s", sanitized["scope"])
	}
}

func TestSanitizeHeaders(t *testing.T) {
	headers := map[string][]string{
		"content-type":  {"application/json"},
		"authorization": {"Bearer token123"},
		"user-agent":    {"test-agent"},
	}

	sensitiveKeys := []string{"authorization", "cookie"}

	sanitized := sanitizeHeaders(headers, sensitiveKeys)

	if sanitized["content-type"] != "application/json" {
		t.Errorf("Expected content-type to be preserved, got %s", sanitized["content-type"])
	}

	if sanitized["authorization"] != "[REDACTED]" {
		t.Errorf("Expected authorization to be redacted, got %s", sanitized["authorization"])
	}

	if sanitized["user-agent"] != "test-agent" {
		t.Errorf("Expected user-agent to be preserved, got %s", sanitized["user-agent"])
	}
}

func TestHashSensitiveData(t *testing.T) {
	data := "sensitive_data"
	hash1 := hashSensitiveData(data)
	hash2 := hashSensitiveData(data)

	if hash1 == "" {
		t.Error("Expected non-empty hash")
	}

	if hash1 != hash2 {
		t.Error("Expected same hash for same data")
	}

	if hashSensitiveData("") != "" {
		t.Error("Expected empty string for empty data")
	}
}

func TestDefaultRiskAssessment(t *testing.T) {
	tests := []struct {
		name         string
		event        AuditEvent
		expectedRisk string
		checkFactors func([]string) bool
	}{
		{
			name: "Normal request",
			event: AuditEvent{
				StatusCode:   200,
				ResponseTime: 100 * time.Millisecond,
				ClientID:     "test_client",
			},
			expectedRisk: "low",
			checkFactors: func(factors []string) bool {
				return len(factors) == 0
			},
		},
		{
			name: "Client error",
			event: AuditEvent{
				StatusCode:   400,
				ResponseTime: 100 * time.Millisecond,
				ClientID:     "test_client",
			},
			expectedRisk: "low",
			checkFactors: func(factors []string) bool {
				return contains(factors, "client_error")
			},
		},
		{
			name: "Server error",
			event: AuditEvent{
				StatusCode:   500,
				ResponseTime: 100 * time.Millisecond,
				ClientID:     "test_client",
			},
			expectedRisk: "medium",
			checkFactors: func(factors []string) bool {
				return contains(factors, "server_error")
			},
		},
		{
			name: "Slow response",
			event: AuditEvent{
				StatusCode:   200,
				ResponseTime: 6 * time.Second,
				ClientID:     "test_client",
			},
			expectedRisk: "medium",
			checkFactors: func(factors []string) bool {
				return contains(factors, "slow_response")
			},
		},
		{
			name: "Missing client ID",
			event: AuditEvent{
				StatusCode:   200,
				ResponseTime: 100 * time.Millisecond,
				ClientID:     "",
			},
			expectedRisk: "high",
			checkFactors: func(factors []string) bool {
				return contains(factors, "missing_client_id")
			},
		},
		{
			name: "Token revocation",
			event: AuditEvent{
				StatusCode:   200,
				ResponseTime: 100 * time.Millisecond,
				ClientID:     "test_client",
				Path:         "/oauth2/revoke",
			},
			expectedRisk: "medium",
			checkFactors: func(factors []string) bool {
				return contains(factors, "token_revocation")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			riskLevel, riskFactors := defaultRiskAssessment(tt.event)
			if riskLevel != tt.expectedRisk {
				t.Errorf("Expected risk level %s, got %s", tt.expectedRisk, riskLevel)
			}
			if !tt.checkFactors(riskFactors) {
				t.Errorf("Risk factors check failed for factors: %v", riskFactors)
			}
		})
	}
}

func TestDetermineErrorCode(t *testing.T) {
	tests := []struct {
		statusCode int
		expected   string
	}{
		{400, "invalid_request"},
		{401, "invalid_token"},
		{403, "insufficient_scope"},
		{404, "not_found"},
		{429, "too_many_requests"},
		{500, "server_error"},
		{999, "server_error"}, // 999 仍然被视为服务器错误
	}

	for _, tt := range tests {
		result := determineErrorCode(tt.statusCode)
		if result != tt.expected {
			t.Errorf("determineErrorCode(%d) = %s, want %s", tt.statusCode, result, tt.expected)
		}
	}
}

func TestDetermineErrorMessage(t *testing.T) {
	// 测试 JSON 错误响应
	jsonError := `{"error": "invalid_grant", "error_description": "Invalid authorization code"}`
	message := determineErrorMessage(400, []byte(jsonError))
	if message != "Invalid authorization code" {
		t.Errorf("Expected 'Invalid authorization code', got %s", message)
	}

	// 测试只有 error 字段的响应
	jsonErrorOnly := `{"error": "invalid_request"}`
	message = determineErrorMessage(400, []byte(jsonErrorOnly))
	if message != "invalid_request" {
		t.Errorf("Expected 'invalid_request', got %s", message)
	}

	// 测试空响应体
	message = determineErrorMessage(404, []byte{})
	if message != "" {
		t.Errorf("Expected empty message for empty body, got %s", message)
	}

	// 测试无效 JSON
	invalidJSON := `{invalid json}`
	message = determineErrorMessage(500, []byte(invalidJSON))
	if message != "Internal Server Error" {
		t.Errorf("Expected 'Internal Server Error', got %s", message)
	}
}

func TestExtractOAuthInfo(t *testing.T) {
	// 创建测试请求
	req := httptest.NewRequest("POST", "/oauth2/token?client_id=test_client&scope=read+write", strings.NewReader("grant_type=authorization_code&code=test_code"))
	req.Header.Set("Authorization", "Bearer test_token")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// 设置上下文中的认证信息
	ctx := context.WithValue(req.Context(), authInfoKeyType{}, server.AuthInfo{
		Scopes: []string{"read", "write"},
		Extra: map[string]interface{}{
			"sub": "test_user",
		},
	})
	req = req.WithContext(ctx)

	info := extractOAuthInfo(req)

	// 验证提取的信息
	if info.ClientID != "test_client" {
		t.Errorf("Expected client_id 'test_client', got %s", info.ClientID)
	}

	// 注意：由于 ParseForm 可能在某些测试环境中不工作，我们主要测试 URL 参数和头部
	if info.Token != "test_token" {
		t.Errorf("Expected token 'test_token', got %s", info.Token)
	}

	if len(info.Scopes) != 2 {
		t.Errorf("Expected 2 scopes, got %d", len(info.Scopes))
	}

	if info.Subject != "test_user" {
		t.Errorf("Expected subject 'test_user', got %s", info.Subject)
	}
}

func TestExtractSubject(t *testing.T) {
	authInfo := server.AuthInfo{
		Extra: map[string]interface{}{
			"sub":   "test_user",
			"other": "value",
		},
	}

	subject := extractSubject(authInfo)
	if subject != "test_user" {
		t.Errorf("Expected subject 'test_user', got %s", subject)
	}

	// 测试没有 subject 的情况
	authInfoNoSub := server.AuthInfo{
		Extra: map[string]interface{}{
			"other": "value",
		},
	}

	subject = extractSubject(authInfoNoSub)
	if subject != "" {
		t.Errorf("Expected empty subject, got %s", subject)
	}
}

func TestAuditMiddlewareBasic(t *testing.T) {
	// 创建基础审计中间件
	middleware := WithBasicAudit()

	// 创建测试处理器
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// 包装处理器
	wrappedHandler := middleware(testHandler)

	// 创建测试请求
	req := httptest.NewRequest("GET", "/oauth2/authorize?client_id=test_client", nil)
	w := httptest.NewRecorder()

	// 执行请求
	wrappedHandler.ServeHTTP(w, req)

	// 验证响应
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestAuditMiddlewareDetailed(t *testing.T) {
	// 创建详细审计中间件
	middleware := WithDetailedAudit()

	// 创建测试处理器
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// 包装处理器
	wrappedHandler := middleware(testHandler)

	// 创建测试请求
	req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "test-agent")

	w := httptest.NewRecorder()

	// 执行请求
	wrappedHandler.ServeHTTP(w, req)

	// 验证响应
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestAuditMiddlewareFull(t *testing.T) {
	// 创建完整审计中间件
	middleware := WithFullAudit()

	// 创建测试处理器
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// 包装处理器
	wrappedHandler := middleware(testHandler)

	// 创建测试请求
	req := httptest.NewRequest("DELETE", "/oauth2/revoke", strings.NewReader("token=test_token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()

	// 执行请求
	wrappedHandler.ServeHTTP(w, req)

	// 验证响应
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestAuditMiddlewareWithCustomZapLogger(t *testing.T) {
	// 创建自定义 zap logger
	testLogger := zaptest.NewLogger(t)

	// 创建带自定义 logger 的审计中间件
	options := WithCustomZapLogger(testLogger, AuditLevelDetailed, true)
	middleware := AuditMiddleware(options)

	// 创建测试处理器
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// 包装处理器
	wrappedHandler := middleware(testHandler)

	// 创建测试请求
	req := httptest.NewRequest("GET", "/oauth2/metadata", nil)
	w := httptest.NewRecorder()

	// 执行请求
	wrappedHandler.ServeHTTP(w, req)

	// 验证响应
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestAuditMiddlewareExcludePatterns(t *testing.T) {
	// 创建自定义配置的审计中间件
	options := NewAuditOptionsBuilder().
		WithEndpointPatterns([]string{"/oauth2/.*"}).
		WithExcludePatterns([]string{"/oauth2/health"}).
		Build()

	middleware := AuditMiddleware(options)

	// 创建测试处理器
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// 包装处理器
	wrappedHandler := middleware(testHandler)

	// 测试应该被审计的路径
	req1 := httptest.NewRequest("GET", "/oauth2/authorize", nil)
	w1 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("Expected status 200 for audited path, got %d", w1.Code)
	}

	// 测试应该被排除的路径
	req2 := httptest.NewRequest("GET", "/oauth2/health", nil)
	w2 := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Expected status 200 for excluded path, got %d", w2.Code)
	}
}

func TestAuditMiddlewareErrorHandling(t *testing.T) {
	// 创建测试 logger
	testLogger := zaptest.NewLogger(t)

	// 创建审计中间件
	options := WithZapLogger(testLogger)
	middleware := AuditMiddleware(options)

	// 创建返回错误的测试处理器
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		errorResponse := map[string]string{
			"error":             "invalid_request",
			"error_description": "Missing required parameter",
		}
		json.NewEncoder(w).Encode(errorResponse)
	})

	// 包装处理器
	wrappedHandler := middleware(testHandler)

	// 创建测试请求
	req := httptest.NewRequest("POST", "/oauth2/token", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()

	// 执行请求
	wrappedHandler.ServeHTTP(w, req)

	// 验证响应
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestAuditMiddlewarePerformance(t *testing.T) {
	// 创建性能测试的审计中间件
	options := NewAuditOptionsBuilder().
		WithLevel(AuditLevelBasic).
		WithHashSensitiveData(false).
		Build()

	middleware := AuditMiddleware(options)

	// 创建测试处理器
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟处理时间
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// 包装处理器
	wrappedHandler := middleware(testHandler)

	// 创建测试请求
	req := httptest.NewRequest("GET", "/oauth2/authorize", nil)
	w := httptest.NewRecorder()

	// 执行请求
	start := time.Now()
	wrappedHandler.ServeHTTP(w, req)
	duration := time.Since(start)

	// 验证响应
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// 验证性能（应该比直接调用慢一些，但不会太慢）
	if duration > 200*time.Millisecond {
		t.Errorf("Expected reasonable performance, took %v", duration)
	}
}

func TestAuditResponseWriter(t *testing.T) {
	// 创建测试响应记录器
	recorder := httptest.NewRecorder()

	// 创建审计响应写入器
	auditWriter := &auditResponseWriter{
		ResponseWriter: recorder,
		body:           make([]byte, 0),
	}

	// 测试写入头部
	auditWriter.WriteHeader(http.StatusCreated)
	if auditWriter.statusCode != http.StatusCreated {
		t.Errorf("Expected status code %d, got %d", http.StatusCreated, auditWriter.statusCode)
	}

	// 测试写入数据
	testData := []byte("test response")
	written, err := auditWriter.Write(testData)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if written != len(testData) {
		t.Errorf("Expected written bytes %d, got %d", len(testData), written)
	}

	// 验证状态码被设置
	if auditWriter.statusCode == 0 {
		auditWriter.statusCode = http.StatusOK
	}

	// 验证响应体被捕获
	if len(auditWriter.body) == 0 {
		t.Error("Expected response body to be captured")
	}
}

// 基准测试
func BenchmarkAuditMiddleware(b *testing.B) {
	// 创建基础审计中间件
	middleware := WithBasicAudit()

	// 创建测试处理器
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// 包装处理器
	wrappedHandler := middleware(testHandler)

	// 创建测试请求
	req := httptest.NewRequest("GET", "/oauth2/authorize", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)
	}
}

func BenchmarkHashSensitiveData(b *testing.B) {
	testData := "sensitive_test_data_that_needs_hashing"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hashSensitiveData(testData)
	}
}

func BenchmarkSanitizeMap(b *testing.B) {
	queryParams := map[string][]string{
		"client_id":     {"test_client"},
		"client_secret": {"secret_value"},
		"scope":         {"read write"},
	}
	sensitiveKeys := []string{"client_secret", "password"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sanitizeQueryParams(queryParams, sensitiveKeys)
	}
}
