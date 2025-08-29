package middleware

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// MinimalAuditLogger 定义审计日志记录器接口
type MinimalAuditLogger interface {
	LogAuditEvent(ctx context.Context, event MinimalAuditEvent)
}

// DefaultMinimalAuditLogger 使用标准log包的简单同步日志记录器
type DefaultMinimalAuditLogger struct{}

// LogAuditEvent 实现MinimalAuditLogger，使用结构化JSON日志记录
func (l *DefaultMinimalAuditLogger) LogAuditEvent(ctx context.Context, event MinimalAuditEvent) {
	logEntry := map[string]interface{}{
		"timestamp":  event.Timestamp.Format(time.RFC3339),
		"method":     event.Method,
		"path":       event.Path,
		"status":     event.StatusCode,
		"ip":         event.ClientIP,
		"user_agent": event.UserAgent,
	}
	jsonLog, _ := json.Marshal(logEntry)
	log.Printf("[AUDIT] %s", string(jsonLog))
}

// MinimalAuditEvent 表示简化的审计事件
type MinimalAuditEvent struct {
	Timestamp  time.Time
	Method     string
	Path       string
	StatusCode int
	ClientIP   string
	UserAgent  string
}

// MinimalAuditMiddleware 是http.Handler中间件，用于审计HTTP请求
type MinimalAuditMiddleware struct {
	Logger MinimalAuditLogger
}

// NewMinimalAuditMiddleware 创建一个新的MinimalAuditMiddleware
func NewMinimalAuditMiddleware(logger MinimalAuditLogger) *MinimalAuditMiddleware {
	if logger == nil {
		logger = &DefaultMinimalAuditLogger{}
	}
	return &MinimalAuditMiddleware{
		Logger: logger,
	}
}

// responseWriter 包装http.ResponseWriter以捕获状态码
type minimalResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader 捕获状态码
func (rw *minimalResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Wrap 实现Middleware接口，包装下一个处理器并添加审计逻辑
func (m *MinimalAuditMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 包装响应写入器以捕获状态码
		rw := &minimalResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// 调用下一个处理器
		next.ServeHTTP(rw, r)

		// 记录审计事件
		event := MinimalAuditEvent{
			Timestamp:  start,
			Method:     r.Method,
			Path:       r.URL.Path,
			StatusCode: rw.statusCode,
			ClientIP:   getClientIP(r),
			UserAgent:  r.UserAgent(),
		}

		m.Logger.LogAuditEvent(r.Context(), event)
	})
}

// getClientIP 获取客户端IP地址
func getClientIP(r *http.Request) string {
	// 检查X-Forwarded-For头
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return forwarded
	}
	// 检查X-Real-IP头
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	// 使用RemoteAddr
	return r.RemoteAddr
}
