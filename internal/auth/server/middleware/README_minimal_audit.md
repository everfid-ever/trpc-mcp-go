# 最小化审计中间件 (Minimal Audit Middleware)

## 概述

这是一个轻量级的HTTP审计中间件，用于记录HTTP请求的基本信息。相比完整的审计中间件，它移除了以下复杂功能：

- ❌ 异步批处理日志记录
- ❌ OAuth 2.1合规性检查
- ❌ 请求/响应体解析和脱敏
- ❌ 复杂的配置选项
- ❌ 合规性规则引擎

## 功能特性

✅ **核心审计功能**
- HTTP方法和路径记录
- 响应状态码记录
- 客户端IP地址记录（支持代理头）
- 用户代理记录
- 时间戳记录

✅ **简单易用**
- 最小化配置
- 同步日志记录
- 标准Go log包支持
- 可扩展的日志记录器接口

## 使用方法

### 基本用法

```go
package main

import (
    "net/http"
    "your-project/internal/auth/server/middleware"
)

func main() {
    // 创建最小化审计中间件
    auditMiddleware := middleware.NewMinimalAuditMiddleware(nil) // 使用默认日志记录器
    
    // 创建你的HTTP处理器
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, World!"))
    })
    
    // 包装处理器
    wrappedHandler := auditMiddleware.Wrap(handler)
    
    // 使用包装后的处理器
    http.Handle("/", wrappedHandler)
    http.ListenAndServe(":8080", nil)
}
```

### 自定义日志记录器

```go
// 实现自定义日志记录器
type CustomLogger struct{}

func (l *CustomLogger) LogAuditEvent(ctx context.Context, event middleware.MinimalAuditEvent) {
    // 自定义日志记录逻辑
    log.Printf("Custom audit: %s %s -> %d", event.Method, event.Path, event.StatusCode)
}

// 使用自定义日志记录器
customLogger := &CustomLogger{}
auditMiddleware := middleware.NewMinimalAuditMiddleware(customLogger)
```

## 审计事件结构

```go
type MinimalAuditEvent struct {
    Timestamp  time.Time // 请求开始时间
    Method     string    // HTTP方法 (GET, POST, etc.)
    Path       string    // 请求路径
    StatusCode int       // HTTP响应状态码
    ClientIP   string    // 客户端IP地址
    UserAgent  string    // 用户代理字符串
}
```

## 日志输出示例

使用默认日志记录器时，输出格式如下：

```
[AUDIT] {"timestamp":"2024-01-01T12:00:00Z","method":"POST","path":"/api/users","status":201,"ip":"192.168.1.100","user_agent":"Mozilla/5.0..."}
```

## 性能特点

- **轻量级**: 只记录必要信息，不解析请求体
- **同步处理**: 无异步开销，适合低延迟要求
- **内存友好**: 不缓存大量数据
- **快速**: 最小化处理逻辑

## 适用场景

- 需要基本HTTP请求审计的简单应用
- 对性能要求较高的生产环境
- 只需要记录请求元数据，不需要内容审计
- 作为更复杂审计系统的起点

## 与完整审计中间件的对比

| 功能 | 最小化版本 | 完整版本 |
|------|------------|----------|
| 基本请求信息 | ✅ | ✅ |
| 响应状态码 | ✅ | ✅ |
| 客户端IP | ✅ | ✅ |
| 异步日志 | ❌ | ✅ |
| OAuth合规性检查 | ❌ | ✅ |
| 请求体解析 | ❌ | ✅ |
| 敏感信息脱敏 | ❌ | ✅ |
| 合规性规则 | ❌ | ✅ |
| 配置复杂度 | 低 | 高 |
| 性能开销 | 低 | 中等 |

## 扩展建议

如果需要更多功能，可以考虑：

1. **添加请求ID**: 在上下文中传递唯一标识符
2. **自定义字段**: 根据业务需求添加额外审计字段
3. **结构化日志**: 集成logrus、zap等结构化日志库
4. **异步处理**: 添加简单的goroutine异步日志记录
5. **过滤规则**: 添加基于路径或方法的过滤逻辑

## 测试

运行测试：

```bash
go test ./internal/auth/server/middleware -v
```

## 注意事项

- 默认日志记录器使用Go标准库的`log`包
- 客户端IP检测支持常见的代理头（X-Forwarded-For, X-Real-IP）
- 中间件会包装`http.ResponseWriter`以捕获状态码
- 所有请求都会被审计，没有过滤机制
