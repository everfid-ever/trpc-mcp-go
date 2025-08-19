package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/middleware"
)

// MetadataHandler creates a handler for metadata endpoints
// This matches the TypeScript implementation using middleware composition
func MetadataHandler(metadata interface{}) http.HandlerFunc {
	// Core handler that just serves JSON - no CORS or method validation
	coreHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(metadata)
	})

	middlewareHandler := middleware.CorsMiddleware(
		middleware.AllowedMethods([]string{"GET"}, func(d middleware.Decision) {
			fmt.Printf("[METHOD AUDIT] allowed=%v reason=%s action=%s path=%s\n",
				d.Allowed, d.Reason, d.Action, d.Resource)
		})(coreHandler),
	)

	// Convert http.Handler to http.HandlerFunc
	return func(w http.ResponseWriter, r *http.Request) {
		middlewareHandler.ServeHTTP(w, r)
	}
}
