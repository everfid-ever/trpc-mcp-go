package middleware

//
//import (
//	"context"
//	"net/http"
//	"time"
//
//	"github.com/google/uuid"
//	"go.uber.org/zap"
//	"go.uber.org/zap/zapcore"
//)
//
//// ZapAuditLogger 使用zap日志库的审计日志记录器
//type ZapAuditLogger struct {
//	logger *zap.Logger
//	fields []zap.Field
//}
//
//// NewZapAuditLogger 创建一个新的ZapAuditLogger
//func NewZapAuditLogger(logger *zap.Logger, fields ...zap.Field) *ZapAuditLogger {
//	if logger == nil {
//		logger = zap.NewNop()
//	}
//	return &ZapAuditLogger{
//		logger: logger,
//		fields: fields,
//	}
//}
//
//// LogAuditEvent 实现MinimalAuditLogger接口，使用zap记录审计事件
//func (l *ZapAuditLogger) LogAuditEvent(ctx context.Context, event MinimalAuditEvent) {
//	// 构建zap字段
//	fields := []zap.Field{
//		zap.Time("timestamp", event.Timestamp),
//		zap.String("method", event.Method),
//		zap.String("path", event.Path),
//		zap.Int("status_code", event.StatusCode),
//		zap.String("client_ip", event.ClientIP),
//		zap.String("user_agent", event.UserAgent),
//	}
//
//	// 添加自定义字段
//	fields = append(fields, l.fields...)
//
//	// 从上下文提取额外信息
//	if requestID := extractRequestID(ctx); requestID != "" {
//		fields = append(fields, zap.String("request_id", requestID))
//	}
//
//	// 根据状态码选择日志级别
//	var logFunc func(msg string, fields ...zap.Field)
//	switch {
//	case event.StatusCode >= 500:
//		logFunc = l.logger.Error
//	case event.StatusCode >= 400:
//		logFunc = l.logger.Warn
//	case event.StatusCode >= 300:
//		logFunc = l.logger.Info
//	default:
//		logFunc = l.logger.Info
//	}
//
//	// 记录审计事件
//	logFunc("HTTP request audited", fields...)
//}
//
//// WithFields 添加额外的字段到日志记录器
//func (l *ZapAuditLogger) WithFields(fields ...zap.Field) *ZapAuditLogger {
//	newLogger := &ZapAuditLogger{
//		logger: l.logger,
//		fields: make([]zap.Field, len(l.fields)+len(fields)),
//	}
//	copy(newLogger.fields, l.fields)
//	copy(newLogger.fields[len(l.fields):], fields)
//	return newLogger
//}
//
//// WithContext 从上下文提取信息并添加到日志记录器
//func (l *ZapAuditLogger) WithContext(ctx context.Context) *ZapAuditLogger {
//	fields := extractContextFields(ctx)
//	return l.WithFields(fields...)
//}
//
//// ZapAuditMiddleware 是集成zap的审计中间件
//type ZapAuditMiddleware struct {
//	Logger              *ZapAuditLogger
//	EnableRequestID     bool
//	EnableContextFields bool
//	LogLevel            zapcore.Level
//}
//
//// ZapOption 是ZapAuditMiddleware的配置选项
//type ZapOption func(*ZapAuditMiddleware)
//
//// WithZapLogger 设置zap日志记录器
//func WithZapLogger(logger *zap.Logger) ZapOption {
//	return func(m *ZapAuditMiddleware) {
//		m.Logger = NewZapAuditLogger(logger)
//	}
//}
//
//// WithRequestID 启用请求ID生成
//func WithRequestID(enable bool) ZapOption {
//	return func(m *ZapAuditMiddleware) {
//		m.EnableRequestID = enable
//	}
//}
//
//// WithContextFields 启用从上下文提取字段
//func WithContextFields(enable bool) ZapOption {
//	return func(m *ZapAuditMiddleware) {
//		m.EnableContextFields = enable
//	}
//}
//
//// WithLogLevel 设置日志级别
//func WithLogLevel(level zapcore.Level) ZapOption {
//	return func(m *ZapAuditMiddleware) {
//		m.LogLevel = level
//	}
//}
//
//// NewZapAuditMiddleware 创建一个新的ZapAuditMiddleware
//func NewZapAuditMiddleware(options ...ZapOption) *ZapAuditMiddleware {
//	m := &ZapAuditMiddleware{
//		Logger:              NewZapAuditLogger(zap.L()),
//		EnableRequestID:     true,
//		EnableContextFields: true,
//		LogLevel:            zapcore.InfoLevel,
//	}
//
//	for _, opt := range options {
//		opt(m)
//	}
//
//	return m
//}
//
//// Wrap 实现Middleware接口，包装下一个处理器并添加审计逻辑
//func (m *ZapAuditMiddleware) Wrap(next http.Handler) http.Handler {
//	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		start := time.Now()
//		ctx := r.Context()
//
//		// 生成请求ID（如果启用）
//		if m.EnableRequestID {
//			requestID := generateRequestID()
//			ctx = context.WithValue(ctx, "request_id", requestID)
//			r = r.WithContext(ctx)
//		}
//
//		// 包装响应写入器以捕获状态码
//		rw := &minimalResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
//
//		// 调用下一个处理器
//		next.ServeHTTP(rw, r)
//
//		// 记录审计事件
//		event := MinimalAuditEvent{
//			Timestamp:  start,
//			Method:     r.Method,
//			Path:       r.URL.Path,
//			StatusCode: rw.statusCode,
//			ClientIP:   getClientIP(r),
//			UserAgent:  r.UserAgent(),
//		}
//
//		// 根据配置选择日志记录器
//		var logger MinimalAuditLogger = m.Logger
//		if m.EnableContextFields {
//			logger = m.Logger.WithContext(ctx)
//		}
//
//		logger.LogAuditEvent(ctx, event)
//	})
//}
//
//// extractRequestID 从上下文提取请求ID
//func extractRequestID(ctx context.Context) string {
//	if requestID, ok := ctx.Value("request_id").(string); ok {
//		return requestID
//	}
//	return ""
//}
//
//// extractContextFields 从上下文提取字段信息
//func extractContextFields(ctx context.Context) []zap.Field {
//	var fields []zap.Field
//
//	// 提取用户信息
//	if userID, ok := ctx.Value("user_id").(string); ok && userID != "" {
//		fields = append(fields, zap.String("user_id", userID))
//	}
//
//	// 提取会话信息
//	if sessionID, ok := ctx.Value("session_id").(string); ok && sessionID != "" {
//		fields = append(fields, zap.String("session_id", sessionID))
//	}
//
//	// 提取认证信息
//	if authMethod, ok := ctx.Value("auth_method").(string); ok && authMethod != "" {
//		fields = append(fields, zap.String("auth_method", authMethod))
//	}
//
//	// 提取租户信息
//	if tenantID, ok := ctx.Value("tenant_id").(string); ok && tenantID != "" {
//		fields = append(fields, zap.String("tenant_id", tenantID))
//	}
//
//	return fields
//}
//
//// generateRequestID 生成唯一的请求ID
//func generateRequestID() string {
//	return uuid.New().String()
//}
