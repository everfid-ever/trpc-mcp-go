package middleware

import (
	"context"
	"net/http"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ExampleZapAuditMiddleware 展示如何使用集成zap的审计中间件
func ExampleZapAuditMiddleware() {
	// 1. 创建zap日志记录器
	config := zap.NewProductionConfig()
	config.OutputPaths = []string{"stdout", "audit.log"}
	config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)

	logger, err := config.Build()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	// 2. 创建审计中间件，使用各种配置选项
	auditMiddleware := NewZapAuditMiddleware(
		WithZapLogger(logger),
		WithRequestID(true),
		WithContextFields(true),
		WithLogLevel(zapcore.InfoLevel),
	)

	// 3. 创建HTTP处理器
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 在上下文中添加业务信息
		ctx := r.Context()
		ctx = context.WithValue(ctx, "user_id", "user123")
		ctx = context.WithValue(ctx, "session_id", "session456")
		ctx = context.WithValue(ctx, "auth_method", "jwt")
		ctx = context.WithValue(ctx, "tenant_id", "tenant789")

		// 更新请求上下文
		r = r.WithContext(ctx)

		// 执行业务逻辑
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, World!"))
	})

	// 4. 包装处理器
	wrappedHandler := auditMiddleware.Wrap(handler)

	// 5. 启动HTTP服务器
	http.Handle("/", wrappedHandler)
	http.ListenAndServe(":8080", nil)
}

// ExampleCustomZapLogger 展示如何创建自定义的zap日志记录器
func ExampleCustomZapLogger() {
	// 创建自定义配置
	config := zap.NewProductionConfig()

	// 自定义时间格式
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	// 自定义字段名称
	config.EncoderConfig.MessageKey = "message"
	config.EncoderConfig.LevelKey = "level"
	config.EncoderConfig.TimeKey = "timestamp"

	// 输出到文件
	config.OutputPaths = []string{"audit.log"}
	config.ErrorOutputPaths = []string{"audit_error.log"}

	logger, err := config.Build()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	// 创建带有自定义字段的审计日志记录器
	zapLogger := NewZapAuditLogger(
		logger,
		zap.String("service", "auth-service"),
		zap.String("version", "1.0.0"),
		zap.String("environment", "production"),
	)

	// 创建中间件
	auditMiddleware := NewZapAuditMiddleware(
		WithZapLogger(logger),
		WithRequestID(true),
		WithContextFields(true),
	)

	// 使用中间件...
	_ = auditMiddleware
}

// ExampleStructuredLogging 展示结构化日志的优势
func ExampleStructuredLogging() {
	// 创建开发环境的日志记录器
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	// 创建审计日志记录器
	zapLogger := NewZapAuditLogger(logger)

	// 模拟审计事件
	event := MinimalAuditEvent{
		Timestamp:  zap.Now(),
		Method:     "POST",
		Path:       "/api/users",
		StatusCode: 201,
		ClientIP:   "192.168.1.100",
		UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}

	// 记录事件 - 这将输出结构化的JSON日志
	zapLogger.LogAuditEvent(context.Background(), event)
}

// ExampleContextAwareLogging 展示上下文感知的日志记录
func ExampleContextAwareLogging() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	zapLogger := NewZapAuditLogger(logger)

	// 创建包含业务信息的上下文
	ctx := context.Background()
	ctx = context.WithValue(ctx, "user_id", "user123")
	ctx = context.WithValue(ctx, "session_id", "session456")
	ctx = context.WithValue(ctx, "auth_method", "jwt")
	ctx = context.WithValue(ctx, "tenant_id", "tenant789")
	ctx = context.WithValue(ctx, "correlation_id", "corr-12345")

	// 使用WithContext创建上下文感知的日志记录器
	contextLogger := zapLogger.WithContext(ctx)

	event := MinimalAuditEvent{
		Timestamp:  zap.Now(),
		Method:     "PUT",
		Path:       "/api/users/123",
		StatusCode: 200,
		ClientIP:   "192.168.1.100",
		UserAgent:  "API-Client/1.0",
	}

	// 记录事件 - 将包含所有上下文字段
	contextLogger.LogAuditEvent(ctx, event)
}

// ExampleLogLevels 展示不同状态码对应的日志级别
func ExampleLogLevels() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	zapLogger := NewZapAuditLogger(logger)

	// 测试不同状态码的日志级别
	testCases := []struct {
		method        string
		path          string
		statusCode    int
		expectedLevel string
	}{
		{"GET", "/health", 200, "info"},
		{"POST", "/api/users", 201, "info"},
		{"GET", "/api/users", 301, "info"},
		{"POST", "/api/users", 400, "warn"},
		{"GET", "/api/users/999", 404, "warn"},
		{"POST", "/api/users", 422, "warn"},
		{"GET", "/api/users", 500, "error"},
		{"POST", "/api/users", 503, "error"},
	}

	for _, tc := range testCases {
		event := MinimalAuditEvent{
			Timestamp:  zap.Now(),
			Method:     tc.method,
			Path:       tc.path,
			StatusCode: tc.statusCode,
			ClientIP:   "192.168.1.100",
			UserAgent:  "test-client",
		}

		// 根据状态码，zap会自动选择合适的日志级别
		zapLogger.LogAuditEvent(context.Background(), event)
	}
}

// ExampleFileOutput 展示如何配置文件输出
func ExampleFileOutput() {
	// 创建文件输出配置
	config := zap.NewProductionConfig()

	// 输出到多个文件
	config.OutputPaths = []string{
		"logs/audit.log",       // 审计日志
		"logs/application.log", // 应用日志
		"stdout",               // 控制台输出
	}

	// 错误日志单独输出
	config.ErrorOutputPaths = []string{
		"logs/audit_error.log",
		"stderr",
	}

	// 确保日志目录存在
	os.MkdirAll("logs", 0755)

	logger, err := config.Build()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	// 创建审计中间件
	auditMiddleware := NewZapAuditMiddleware(
		WithZapLogger(logger),
		WithRequestID(true),
		WithContextFields(true),
	)

	// 使用中间件...
	_ = auditMiddleware
}
