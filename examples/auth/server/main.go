package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/handler"
)

// 模拟客户端存储实现
type MockClientStore struct {
	clients map[string]auth.OAuthClientInformationFull
}

func NewMockClientStore() *MockClientStore {
	return &MockClientStore{
		clients: make(map[string]auth.OAuthClientInformationFull),
	}
}

func (m *MockClientStore) RegisterClient(clientInfo auth.OAuthClientInformationFull) (*auth.OAuthClientInformationFull, error) {
	clientID := clientInfo.OAuthClientInformation.ClientID
	m.clients[clientID] = clientInfo
	log.Printf("✅ 客户端注册成功: %s", clientID)
	return &clientInfo, nil
}

func (m *MockClientStore) GetClient(clientID string) (*auth.OAuthClientInformationFull, error) {
	if client, exists := m.clients[clientID]; exists {
		return &client, nil
	}
	return nil, fmt.Errorf("client not found")
}

func (m *MockClientStore) ListClients() map[string]auth.OAuthClientInformationFull {
	return m.clients
}

// 启动测试服务器
func startTestServer() {
	// 创建存储
	clientStore := NewMockClientStore()

	// 配置注册处理器选项
	registrationOptions := handler.ClientRegistrationHandlerOptions{
		ClientsStore: clientStore,
		RateLimit: &handler.RateLimitConfig{
			WindowMs: 60000, // 1分钟
			Max:      10,    // 最多10个请求
		},
	}

	// 创建Gin路由器
	r := gin.Default()

	// CORS中间件
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.Status(http.StatusOK)
			return
		}
		c.Next()
	})

	// 注册端点
	r.POST("/register", handler.ClientRegistrationHandler(registrationOptions))

	// 元数据端点 - 显示支持的功能
	oauthMetadata := auth.OAuthMetadata{
		Issuer:                            "http://localhost:8080",
		AuthorizationEndpoint:             "http://localhost:8080/authorize",
		TokenEndpoint:                     "http://localhost:8080/token",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
	}
	registrationEndpoint := "http://localhost:8080/register"
	oauthMetadata.RegistrationEndpoint = &registrationEndpoint

	r.GET("/.well-known/oauth-authorization-server", handler.MetadataHandlerGin(oauthMetadata))

	// 调试端点 - 查看已注册的客户端
	r.GET("/debug/clients", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"clients": clientStore.ListClients(),
		})
	})

	log.Println("🚀 OAuth测试服务器启动在 http://localhost:8080")
	log.Println("📋 可用端点:")
	log.Println("   POST /register - 客户端注册")
	log.Println("   GET /.well-known/oauth-authorization-server - 服务器元数据")
	log.Println("   GET /debug/clients - 调试：查看已注册客户端")

	if err := r.Run(":8080"); err != nil {
		log.Fatal("服务器启动失败:", err)
	}
}

// 测试客户端注册
func testClientRegistration() {
	time.Sleep(2 * time.Second) // 等待服务器启动

	fmt.Println("\n🧪 开始测试客户端注册链路...")

	// 测试案例1: 机密客户端注册
	fmt.Println("\n📝 测试1: 注册机密客户端")
	testCase1 := auth.OAuthClientMetadata{
		RedirectUris:            []string{"https://example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_post",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientName:              "测试应用1",
		Scope:                   "read write",
	}

	result1, err := registerClient(testCase1)
	if err != nil {
		log.Printf("❌ 测试1失败: %v", err)
	} else {
		log.Printf("✅ 测试1成功:")
		log.Printf("   Client ID: %s", result1.ClientID)
		log.Printf("   Client Secret: %s", result1.ClientSecret)
		log.Printf("   Client Name: %s", result1.ClientName)
	}

	// 测试案例2: 公共客户端注册
	fmt.Println("\n📝 测试2: 注册公共客户端")
	testCase2 := auth.OAuthClientMetadata{
		RedirectUris:            []string{"https://mobile-app.com/callback"},
		TokenEndpointAuthMethod: "none", // 公共客户端
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ClientName:              "移动应用",
		Scope:                   "read",
	}

	result2, err := registerClient(testCase2)
	if err != nil {
		log.Printf("❌ 测试2失败: %v", err)
	} else {
		log.Printf("✅ 测试2成功:")
		log.Printf("   Client ID: %s", result2.ClientID)
		log.Printf("   Client Secret: %s (公共客户端应为空)", result2.ClientSecret)
		log.Printf("   Client Name: %s", result2.ClientName)
	}

	// 测试案例3: 错误请求
	fmt.Println("\n📝 测试3: 无效请求（缺少必要字段）")
	testCase3 := auth.OAuthClientMetadata{
		RedirectUris: []string{"https://example.com/callback"},
		// 缺少 TokenEndpointAuthMethod
	}

	_, err = registerClient(testCase3)
	if err != nil {
		log.Printf("✅ 测试3成功: 正确拒绝了无效请求: %v", err)
	} else {
		log.Printf("❌ 测试3失败: 应该拒绝无效请求")
	}

	// 验证元数据端点
	fmt.Println("\n📝 测试4: 验证服务器元数据")
	testMetadata()

	fmt.Println("\n🎉 测试完成！")
}

// 注册客户端的辅助函数
func registerClient(metadata auth.OAuthClientMetadata) (auth.OAuthClientInformationFull, error) {
	jsonData, err := json.Marshal(metadata)
	if err != nil {
		return auth.OAuthClientInformationFull{}, err
	}

	resp, err := http.Post("http://localhost:8080/register", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return auth.OAuthClientInformationFull{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return auth.OAuthClientInformationFull{}, err
	}

	if resp.StatusCode != http.StatusCreated {
		return auth.OAuthClientInformationFull{}, fmt.Errorf("注册失败 (状态码: %d): %s", resp.StatusCode, string(body))
	}

	var result auth.OAuthClientInformationFull
	if err := json.Unmarshal(body, &result); err != nil {
		return auth.OAuthClientInformationFull{}, err
	}

	return result, nil
}

// 测试元数据端点
func testMetadata() {
	resp, err := http.Get("http://localhost:8080/.well-known/oauth-authorization-server")
	if err != nil {
		log.Printf("❌ 元数据请求失败: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("❌ 元数据端点返回错误状态码: %d", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("❌ 读取元数据响应失败: %v", err)
		return
	}

	var metadata auth.OAuthMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		log.Printf("❌ 解析元数据失败: %v", err)
		return
	}

	log.Printf("✅ 元数据端点正常:")
	log.Printf("   Issuer: %s", metadata.Issuer)
	log.Printf("   Registration Endpoint: %s", *metadata.RegistrationEndpoint)
	log.Printf("   支持的授权类型: %v", metadata.GrantTypesSupported)
}

func main() {
	// 启动测试
	go func() {
		testClientRegistration()
	}()

	// 启动服务器（这会阻塞）
	startTestServer()
}
