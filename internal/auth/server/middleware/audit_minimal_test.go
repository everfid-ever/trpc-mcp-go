package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// MockMinimalAuditLogger 用于测试的模拟日志记录器
type MockMinimalAuditLogger struct {
	Events []MinimalAuditEvent
}

func (m *MockMinimalAuditLogger) LogAuditEvent(ctx context.Context, event MinimalAuditEvent) {
	m.Events = append(m.Events, event)
}

func TestMinimalAuditMiddleware(t *testing.T) {
	// 创建模拟日志记录器
	mockLogger := &MockMinimalAuditLogger{}

	// 创建中间件
	middleware := NewMinimalAuditMiddleware(mockLogger)

	// 创建测试处理器
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// 包装处理器
	wrappedHandler := middleware.Wrap(handler)

	// 创建测试请求
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("User-Agent", "test-agent")

	// 创建响应记录器
	w := httptest.NewRecorder()

	// 执行请求
	wrappedHandler.ServeHTTP(w, req)

	// 验证响应
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}

	// 验证审计事件
	if len(mockLogger.Events) != 1 {
		t.Fatalf("Expected 1 audit event, got %d", len(mockLogger.Events))
	}

	event := mockLogger.Events[0]
	if event.Method != "GET" {
		t.Errorf("Expected method GET, got %s", event.Method)
	}
	if event.Path != "/test" {
		t.Errorf("Expected path /test, got %s", event.Path)
	}
	if event.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, event.StatusCode)
	}
	if event.ClientIP != "192.168.1.1:12345" {
		t.Errorf("Expected client IP 192.168.1.1:12345, got %s", event.ClientIP)
	}
	if event.UserAgent != "test-agent" {
		t.Errorf("Expected user agent test-agent, got %s", event.UserAgent)
	}

	// 验证时间戳
	if event.Timestamp.IsZero() {
		t.Error("Expected non-zero timestamp")
	}
}

func TestMinimalAuditMiddlewareWithNilLogger(t *testing.T) {
	// 测试使用nil日志记录器时是否使用默认记录器
	middleware := NewMinimalAuditMiddleware(nil)

	if middleware.Logger == nil {
		t.Error("Expected default logger to be set when nil logger is provided")
	}

	// 验证默认记录器类型
	_, ok := middleware.Logger.(*DefaultMinimalAuditLogger)
	if !ok {
		t.Error("Expected default logger to be of type DefaultMinimalAuditLogger")
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expectedIP string
	}{
		{
			name:       "X-Forwarded-For header",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.1"},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "10.0.0.1",
		},
		{
			name:       "X-Real-IP header",
			headers:    map[string]string{"X-Real-IP": "10.0.0.2"},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "10.0.0.2",
		},
		{
			name:       "RemoteAddr fallback",
			headers:    map[string]string{},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "192.168.1.1:12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr

			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			ip := getClientIP(req)
			if ip != tt.expectedIP {
				t.Errorf("Expected IP %s, got %s", tt.expectedIP, ip)
			}
		})
	}
}

func TestDefaultMinimalAuditLogger(t *testing.T) {
	logger := &DefaultMinimalAuditLogger{}

	event := MinimalAuditEvent{
		Timestamp:  time.Now(),
		Method:     "POST",
		Path:       "/api/test",
		StatusCode: 201,
		ClientIP:   "127.0.0.1",
		UserAgent:  "test-agent",
	}

	// 这个测试主要是确保没有panic
	logger.LogAuditEvent(context.Background(), event)
}
