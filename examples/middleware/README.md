# MCP 中间件示例

这个目录包含了使用 tRPC-MCP-Go 新中间件系统的示例代码。

## 中间件系统概述

新的中间件系统参考了 tRPC-A2A-Go 的设计，提供了以下特性：

### 1. 中间件接口

```go
type Middleware interface {
    Wrap(next http.Handler) http.Handler
}
```

### 2. 中间件链

```go
type MiddlewareChain []Middleware

func (chain MiddlewareChain) Wrap(handler http.Handler) http.Handler
```

### 3. 配置选项

- `WithMiddleware()`: 添加中间件接口
- `WithMiddlewareFunc()`: 添加函数式中间件

## 使用方式

### 基本用法

```go
server := mcp.NewServer("example", "1.0.0",
    mcp.WithMiddleware(
        &LoggingMiddleware{},
        &RequestIDMiddleware{},
    ),
)
```

### 函数式中间件

```go
server := mcp.NewServer("example", "1.0.0",
    mcp.WithMiddlewareFunc(
        func(next http.Handler) http.Handler {
            return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                log.Printf("Request: %s %s", r.Method, r.URL.Path)
                next.ServeHTTP(w, r)
            })
        },
    ),
)
```

## 统一安全中间件

### 1. 统一安全中间件概述

新的统一安全中间件整合了多种安全功能，提供配置化的安全解决方案：

```go
// 使用预定义的安全配置
securityConfig := mcp.DefaultSecurity()
securityMiddleware := mcp.NewSecurityMiddleware(securityConfig)

// 使用构建器模式自定义配置
customConfig := mcp.NewSecurityConfig().
    WithAllowedMethods("GET", "POST").
    WithCORS().
        AllowOrigins("https://example.com").
        End().
    WithSecurityHeaders().
        WithContentTypeOptions().
        WithFrameOptions().
        End().
    WithRateLimit(100, time.Minute).
        PerIP().
        End().
    Build()

securityMiddleware := mcp.NewSecurityMiddleware(customConfig)
```

### 2. 支持的安全功能

- **HTTP 方法限制**: 限制允许的 HTTP 方法
- **CORS 配置**: 跨域资源共享策略
- **安全头**: 各种安全相关的 HTTP 头
- **速率限制**: 基于 IP 或用户的请求限制
- **TLS 要求**: HTTPS 和 TLS 版本控制
- **IP 过滤**: IP 地址白名单/黑名单
- **请求限制**: 请求体大小和头部大小限制

### 3. 预定义配置

```go
// 默认安全配置
defaultConfig := mcp.DefaultSecurity()

// 严格安全配置
strictConfig := mcp.StrictSecurity()

// API 安全配置
apiConfig := mcp.APISecurity()
```

## 中间件最佳实践

### 1. 单一职责原则

每个中间件应该专注于一个核心功能：

```go
// ✅ 好的做法：使用统一安全中间件
securityMiddleware := mcp.NewSecurityMiddleware(securityConfig)

// ✅ 好的做法：独立的审计中间件
auditMiddleware := mcp.NewAuditMiddleware(auditLogger)

// ❌ 不好的做法：混合多种职责
// 不要在中间件中嵌入回调函数
```

### 2. 中间件链的正确顺序

```go
server := mcp.NewServer("example", "1.0.0",
    // 1. 审计中间件（最先执行，捕获所有事件）
    mcp.WithMiddleware(
        mcp.NewAuditMiddleware(auditLogger),
    ),
    // 2. 统一安全中间件（整合多种安全功能）
    mcp.WithMiddleware(
        mcp.NewSecurityMiddleware(securityConfig),
    ),
    // 3. 业务逻辑中间件
    mcp.WithMiddleware(
        &BusinessLogicMiddleware{},
    ),
)
```

### 3. 独立的审计系统

```go
// 创建专门的审计记录器
type FileAuditLogger struct {
    filename string
}

func (f *FileAuditLogger) LogEvent(event mcp.AuditEvent) error {
    // 实现审计日志记录逻辑
    return nil
}

// 使用独立的审计中间件
auditLogger := &FileAuditLogger{filename: "audit.log"}
auditMiddleware := mcp.NewAuditMiddleware(auditLogger)
```

## 中间件使用示例

### 1. 统一安全中间件（推荐）

```go
// 使用预定义配置
securityConfig := mcp.DefaultSecurity()
securityMiddleware := mcp.NewSecurityMiddleware(securityConfig)

server := mcp.NewServer("example", "1.0.0",
    mcp.WithMiddleware(securityMiddleware),
)
```

### 2. 独立中间件（向后兼容）

```go
// 仍然可以使用独立的中间件
allowedMethodMiddleware := mcp.NewAllowedMethodMiddleware([]string{"POST", "GET"})
auditMiddleware := mcp.NewAuditMiddleware(auditLogger)

server := mcp.NewServer("example", "1.0.0",
    mcp.WithMiddleware(
        auditMiddleware,           // 审计
        allowedMethodMiddleware,   // 方法验证
    ),
)
```

### 3. 混合使用

```go
// 可以混合使用统一安全中间件和独立中间件
securityMiddleware := mcp.NewSecurityMiddleware(securityConfig)
customMiddleware := &CustomMiddleware{}

server := mcp.NewServer("example", "1.0.0",
    mcp.WithMiddleware(
        mcp.NewAuditMiddleware(auditLogger),  // 审计
        securityMiddleware,                    // 统一安全
        customMiddleware,                      // 自定义中间件
    ),
)
```

## 自定义中间件

### 实现中间件接口

```go
type CustomMiddleware struct {
    // 配置字段
}

func (m *CustomMiddleware) Wrap(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // 中间件逻辑
        next.ServeHTTP(w, r)
    })
}
```

### 中间件执行顺序

中间件按照以下顺序执行：
1. 第一个中间件是最外层的包装器
2. 中间件按逆序应用，确保正确的执行顺序
3. 所有中间件都会应用到 HTTP 请求上

## 运行示例

### 基本中间件示例

```bash
cd examples/middleware
go run main.go
```

### 统一安全中间件示例

```bash
cd examples/middleware
go run unified_security_example.go
```

### AllowedMethod 中间件示例

```bash
cd examples/middleware
go run allowed_method_example.go
```

## 兼容性

新的中间件系统完全向后兼容现有的代码。现有的 `AllowedMethods` 函数仍然可以正常工作，但现在也可以通过新的接口系统使用。

## 特性

- ✅ 类型安全的中间件接口
- ✅ 中间件链式组合
- ✅ 函数式中间件支持
- ✅ 向后兼容性
- ✅ 灵活的配置选项
- ✅ 统一的错误处理
