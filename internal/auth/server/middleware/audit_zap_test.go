package middleware

//
//import (
//	"context"
//	"net/http"
//	"net/http/httptest"
//	"testing"
//	"time"
//
//	"go.uber.org/zap"
//	"go.uber.org/zap/zapcore"
//	"go.uber.org/zap/zaptest/observer"
//)
//
//func TestZapAuditLogger(t *testing.T) {
//	// 创建观察者日志记录器用于测试
//	core, obs := observer.New(zapcore.InfoLevel)
//	logger := zap.New(core)
//
//	zapLogger := NewZapAuditLogger(logger)
//	event := MinimalAuditEvent{
//		Timestamp:  time.Now(),
//		Method:     "POST",
//		Path:       "/api/test",
//		StatusCode: 201,
//		ClientIP:   "127.0.0.1",
//		UserAgent:  "test-agent",
//	}
//
//	// 记录审计事件
//	zapLogger.LogAuditEvent(context.Background(), event)
//
//	// 验证日志记录
//	if len(obs.Logs()) != 1 {
//		t.Fatalf("Expected 1 log entry, got %d", len(obs.Logs()))
//	}
//
//	logEntry := obs.Logs()[0]
//	if logEntry.Message != "HTTP request audited" {
//		t.Errorf("Expected message 'HTTP request audited', got '%s'", logEntry.Message)
//	}
//
//	// 验证字段
//	expectedFields := map[string]interface{}{
//		"method":      "POST",
//		"path":        "/api/test",
//		"status_code": 201,
//		"client_ip":   "127.0.0.1",
//		"user_agent":  "test-agent",
//	}
//
//	for field, expectedValue := range expectedFields {
//		if !obs.FilterField(field).FilterMessage("HTTP request audited").Len() > 0 {
//			t.Errorf("Field '%s' not found in log entry", field)
//		}
//	}
//}
//
//func TestZapAuditLoggerWithFields(t *testing.T) {
//	core, obs := observer.New(zapcore.InfoLevel)
//	logger := zap.New(core)
//
//	zapLogger := NewZapAuditLogger(logger, zap.String("service", "test-service"))
//	event := MinimalAuditEvent{
//		Timestamp:  time.Now(),
//		Method:     "GET",
//		Path:       "/health",
//		StatusCode: 200,
//		ClientIP:   "127.0.0.1",
//		UserAgent:  "test-agent",
//	}
//
//	zapLogger.LogAuditEvent(context.Background(), event)
//
//	// 验证自定义字段
//	if !obs.FilterField("service").FilterMessage("HTTP request audited").Len() > 0 {
//		t.Error("Custom field 'service' not found in log entry")
//	}
//}
//
//func TestZapAuditLoggerWithContext(t *testing.T) {
//	core, obs := observer.New(zapcore.InfoLevel)
//	logger := zap.New(core)
//
//	zapLogger := NewZapAuditLogger(logger)
//	ctx := context.WithValue(context.Background(), "user_id", "user123")
//	ctx = context.WithValue(ctx, "session_id", "session456")
//
//	event := MinimalAuditEvent{
//		Timestamp:  time.Now(),
//		Method:     "PUT",
//		Path:       "/api/users",
//		StatusCode: 200,
//		ClientIP:   "127.0.0.1",
//		UserAgent:  "test-agent",
//	}
//
//	// 使用WithContext
//	contextLogger := zapLogger.WithContext(ctx)
//	contextLogger.LogAuditEvent(ctx, event)
//
//	// 验证上下文字段
//	if !obs.FilterField("user_id").FilterMessage("HTTP request audited").Len() > 0 {
//		t.Error("Context field 'user_id' not found in log entry")
//	}
//	if !obs.FilterField("session_id").FilterMessage("HTTP request audited").Len() > 0 {
//		t.Error("Context field 'session_id' not found in log entry")
//	}
//}
//
//func TestZapAuditLoggerLogLevels(t *testing.T) {
//	tests := []struct {
//		name           string
//		statusCode     int
//		expectedLevel  zapcore.Level
//		expectedMethod string
//	}{
//		{"Success", 200, zapcore.InfoLevel, "Info"},
//		{"Redirect", 301, zapcore.InfoLevel, "Info"},
//		{"ClientError", 400, zapcore.WarnLevel, "Warn"},
//		{"NotFound", 404, zapcore.WarnLevel, "Warn"},
//		{"ServerError", 500, zapcore.ErrorLevel, "Error"},
//		{"InternalError", 503, zapcore.ErrorLevel, "Error"},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			core, obs := observer.New(zapcore.DebugLevel)
//			logger := zap.New(core)
//
//			zapLogger := NewZapAuditLogger(logger)
//			event := MinimalAuditEvent{
//				Timestamp:  time.Now(),
//				Method:     "GET",
//				Path:       "/test",
//				StatusCode: tt.statusCode,
//				ClientIP:   "127.0.0.1",
//				UserAgent:  "test-agent",
//			}
//
//			zapLogger.LogAuditEvent(context.Background(), event)
//
//			// 验证日志级别
//			logs := obs.FilterMessage("HTTP request audited").All()
//			if len(logs) != 1 {
//				t.Fatalf("Expected 1 log entry, got %d", len(logs))
//			}
//
//			if logs[0].Level != tt.expectedLevel {
//				t.Errorf("Expected level %v, got %v", tt.expectedLevel, logs[0].Level)
//			}
//		})
//	}
//}
//
//func TestZapAuditMiddleware(t *testing.T) {
//	// 创建观察者日志记录器
//	core, obs := observer.New(zapcore.InfoLevel)
//	logger := zap.New(core)
//
//	// 创建中间件
//	middleware := NewZapAuditMiddleware(
//		WithZapLogger(logger),
//		WithRequestID(true),
//		WithContextFields(true),
//	)
//
//	// 创建测试处理器
//	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		w.WriteHeader(http.StatusCreated)
//		w.Write([]byte("test response"))
//	})
//
//	// 包装处理器
//	wrappedHandler := middleware.Wrap(handler)
//
//	// 创建测试请求
//	req := httptest.NewRequest("POST", "/api/test", nil)
//	req.RemoteAddr = "192.168.1.1:12345"
//	req.Header.Set("User-Agent", "test-agent")
//
//	// 创建响应记录器
//	w := httptest.NewRecorder()
//
//	// 执行请求
//	wrappedHandler.ServeHTTP(w, req)
//
//	// 验证响应
//	if w.Code != http.StatusCreated {
//		t.Errorf("Expected status code %d, got %d", http.StatusCreated, w.Code)
//	}
//
//	// 验证日志记录
//	logs := obs.FilterMessage("HTTP request audited").All()
//	if len(logs) != 1 {
//		t.Fatalf("Expected 1 log entry, got %d", len(logs))
//	}
//
//	logEntry := logs[0]
//	expectedFields := map[string]interface{}{
//		"method":      "POST",
//		"path":        "/api/test",
//		"status_code": 201,
//		"client_ip":   "192.168.1.1:12345",
//		"user_agent":  "test-agent",
//	}
//
//	for field, expectedValue := range expectedFields {
//		if !obs.FilterField(field).FilterMessage("HTTP request audited").Len() > 0 {
//			t.Errorf("Field '%s' not found in log entry", field)
//		}
//	}
//
//	// 验证请求ID
//	if !obs.FilterField("request_id").FilterMessage("HTTP request audited").Len() > 0 {
//		t.Error("Request ID not found in log entry")
//	}
//}
//
//func TestZapAuditMiddlewareWithNilLogger(t *testing.T) {
//	// 测试使用nil日志记录器时是否使用默认记录器
//	middleware := NewZapAuditMiddleware()
//
//	if middleware.Logger == nil {
//		t.Error("Expected default logger to be set when nil logger is provided")
//	}
//}
//
//func TestZapAuditMiddlewareOptions(t *testing.T) {
//	core, obs := observer.New(zapcore.InfoLevel)
//	logger := zap.New(core)
//
//	// 测试禁用请求ID
//	middleware := NewZapAuditMiddleware(
//		WithZapLogger(logger),
//		WithRequestID(false),
//	)
//
//	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		w.WriteHeader(http.StatusOK)
//	})
//
//	wrappedHandler := middleware.Wrap(handler)
//	req := httptest.NewRequest("GET", "/test", nil)
//	w := httptest.NewRecorder()
//
//	wrappedHandler.ServeHTTP(w, req)
//
//	// 验证没有请求ID字段
//	logs := obs.FilterMessage("HTTP request audited").All()
//	if len(logs) != 1 {
//		t.Fatalf("Expected 1 log entry, got %d", len(logs))
//	}
//
//	// 检查请求ID字段不存在
//	if obs.FilterField("request_id").FilterMessage("HTTP request audited").Len() > 0 {
//		t.Error("Request ID should not be present when disabled")
//	}
//}
//
//func TestExtractContextFields(t *testing.T) {
//	ctx := context.Background()
//	ctx = context.WithValue(ctx, "user_id", "user123")
//	ctx = context.WithValue(ctx, "session_id", "session456")
//	ctx = context.WithValue(ctx, "auth_method", "jwt")
//	ctx = context.WithValue(ctx, "tenant_id", "tenant789")
//
//	fields := extractContextFields(ctx)
//
//	expectedFields := map[string]string{
//		"user_id":     "user123",
//		"session_id":  "session456",
//		"auth_method": "jwt",
//		"tenant_id":   "tenant789",
//	}
//
//	if len(fields) != len(expectedFields) {
//		t.Errorf("Expected %d fields, got %d", len(expectedFields), len(fields))
//	}
//
//	// 验证字段值
//	for _, field := range fields {
//		if field.Key == "user_id" && field.String != "user123" {
//			t.Errorf("Expected user_id 'user123', got '%s'", field.String)
//		}
//		if field.Key == "session_id" && field.String != "session456" {
//			t.Errorf("Expected session_id 'session456', got '%s'", field.String)
//		}
//		if field.Key == "auth_method" && field.String != "jwt" {
//			t.Errorf("Expected auth_method 'jwt', got '%s'", field.String)
//		}
//		if field.Key == "tenant_id" && field.String != "tenant789" {
//			t.Errorf("Expected tenant_id 'tenant789', got '%s'", field.String)
//		}
//	}
//}
//
//func TestGenerateRequestID(t *testing.T) {
//	// 测试生成多个请求ID是否唯一
//	ids := make(map[string]bool)
//	for i := 0; i < 100; i++ {
//		id := generateRequestID()
//		if ids[id] {
//			t.Errorf("Duplicate request ID generated: %s", id)
//		}
//		ids[id] = true
//	}
//}
