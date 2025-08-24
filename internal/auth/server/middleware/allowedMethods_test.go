package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAllowedMethods 测试 AllowedMethods 中间件
func TestAllowedMethods(t *testing.T) {
	// 创建测试路由
	createTestHandler := func() http.Handler {
		mux := http.NewServeMux()
		// 定义 /test 路由，仅支持 GET
		mux.Handle("/test", AllowedMethods([]string{"GET"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("GET success"))
		})))
		return mux
	}

	// 测试用例 1：允许指定的 HTTP 方法
	t.Run("allows specified HTTP method", func(t *testing.T) {
		handler := createTestHandler()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
		if body := rr.Body.String(); body != "GET success" {
			t.Errorf("expected body %q, got %q", "GET success", body)
		}
	})

	// 测试用例 2：对未指定的 HTTP 方法返回 405
	t.Run("returns 405 for unspecified HTTP methods", func(t *testing.T) {
		methods := []string{"POST", "PUT", "DELETE", "PATCH"}

		for _, method := range methods {
			t.Run(method, func(t *testing.T) {
				handler := createTestHandler()
				req := httptest.NewRequest(method, "/test", nil)
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)

				if rr.Code != http.StatusMethodNotAllowed {
					t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
				}

				var response map[string]string
				if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				expected := map[string]string{
					"error":             "method not allowed",
					"error_description": "The method " + method + " is not allowed for this endpoint",
				}
				if response["error"] != expected["error"] || response["error_description"] != expected["error_description"] {
					t.Errorf("expected response %v, got %v", expected, response)
				}
			})
		}
	})

	// 测试用例 3：检查 Allow 响应头
	t.Run("includes Allow header with specified methods", func(t *testing.T) {
		handler := createTestHandler()
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if allow := rr.Header().Get("Allow"); allow != "GET" {
			t.Errorf("expected Allow header %q, got %q", "GET", allow)
		}
	})

	// 测试用例 4：支持多个允许的 HTTP 方法
	t.Run("works with multiple allowed methods", func(t *testing.T) {
		// 创建支持 GET 和 POST 的路由
		mux := http.NewServeMux()
		mux.Handle("/multi", AllowedMethods([]string{"GET", "POST"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte("GET"))
			} else if r.Method == http.MethodPost {
				_, _ = w.Write([]byte("POST"))
			}
		})))

		// 测试允许的方法
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			t.Run(method, func(t *testing.T) {
				req := httptest.NewRequest(method, "/multi", nil)
				rr := httptest.NewRecorder()
				mux.ServeHTTP(rr, req)

				if rr.Code != http.StatusOK {
					t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
				}
				expectedBody := strings.ToUpper(method)
				if body := rr.Body.String(); body != expectedBody {
					t.Errorf("expected body %q, got %q", expectedBody, body)
				}
			})
		}

		// 测试未允许的方法
		t.Run("PUT", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/multi", nil)
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
			}
			if allow := rr.Header().Get("Allow"); allow != "GET, POST" {
				t.Errorf("expected Allow header %q, got %q", "GET, POST", allow)
			}
		})
	})
}
