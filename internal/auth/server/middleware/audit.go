package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Middleware interface definition
type Middleware interface {
	Wrap(next http.Handler) http.Handler
}

// AuditLogger defines the interface for logging audit events.
type AuditLogger interface {
	LogAuditEvent(ctx context.Context, event AuditEvent)
}

// DefaultAuditLogger is a simple synchronous logger using the standard log package.
type DefaultAuditLogger struct{}

// LogAuditEvent implements AuditLogger using std log.
func (l *DefaultAuditLogger) LogAuditEvent(ctx context.Context, event AuditEvent) {
	log.Printf("[OAuth Audit] Timestamp: %s, TraceID: %s, Type: %s, Details: %+v",
		event.Timestamp.Format(time.RFC3339), event.TraceID, event.Type, event.Details)
}

// AsyncAuditLogger wraps an AuditLogger for asynchronous logging.
type AsyncAuditLogger struct {
	inner AuditLogger
	wg    sync.WaitGroup
	ch    chan AuditEventWithCtx
}

// AuditEventWithCtx bundles the event and context for async processing.
type AuditEventWithCtx struct {
	Ctx   context.Context
	Event AuditEvent
}

// NewAsyncAuditLogger creates an async logger with a specified buffer size.
func NewAsyncAuditLogger(inner AuditLogger, bufferSize int) *AsyncAuditLogger {
	if inner == nil {
		inner = &DefaultAuditLogger{}
	}
	al := &AsyncAuditLogger{
		inner: inner,
		ch:    make(chan AuditEventWithCtx, bufferSize),
	}
	al.wg.Add(1)
	go func() {
		defer al.wg.Done()
		for e := range al.ch {
			al.inner.LogAuditEvent(e.Ctx, e.Event)
		}
	}()
	return al
}

// LogAuditEvent queues the event for async logging.
func (al *AsyncAuditLogger) LogAuditEvent(ctx context.Context, event AuditEvent) {
	select {
	case al.ch <- AuditEventWithCtx{Ctx: ctx, Event: event}:
	default:
		log.Printf("[AsyncAuditLogger] Buffer full, logging synchronously: %+v", event)
		al.inner.LogAuditEvent(ctx, event)
	}
}

// Close waits for all queued events to be logged and closes the channel.
func (al *AsyncAuditLogger) Close() {
	close(al.ch)
	al.wg.Wait()
}

// AuditEvent represents a structured audit event for OAuth operations.
type AuditEvent struct {
	Timestamp time.Time
	TraceID   string
	Type      string // e.g., "AuthorizeRequest", "TokenRequest", "RegisterRequest", "RevokeRequest", "MetadataRequest"
	Details   map[string]interface{}
}

// AuditMiddleware is an http.Handler middleware for auditing OAuth 2.1 core endpoints.
type AuditMiddleware struct {
	Logger              AuditLogger
	MaskSensitiveFields bool
	CustomMaskedFields  []string
	MaxBodySizeToAudit  int64
	EnableOAuth21Checks bool
	CoreEndpoints       []string
}

// Option is a functional option for configuring AuditMiddleware.
type Option func(*AuditMiddleware)

// WithLogger sets the logger.
func WithLogger(logger AuditLogger) Option {
	return func(m *AuditMiddleware) {
		m.Logger = logger
	}
}

// WithMaskSensitiveFields sets whether to mask sensitive fields.
func WithMaskSensitiveFields(mask bool) Option {
	return func(m *AuditMiddleware) {
		m.MaskSensitiveFields = mask
	}
}

// WithCustomMaskedFields sets additional fields to mask.
func WithCustomMaskedFields(fields []string) Option {
	return func(m *AuditMiddleware) {
		m.CustomMaskedFields = fields
	}
}

// WithMaxBodySizeToAudit sets the max body size to audit.
func WithMaxBodySizeToAudit(size int64) Option {
	return func(m *AuditMiddleware) {
		m.MaxBodySizeToAudit = size
	}
}

// WithEnableOAuth21Checks sets whether to enable OAuth 2.1 checks.
func WithEnableOAuth21Checks(enable bool) Option {
	return func(m *AuditMiddleware) {
		m.EnableOAuth21Checks = enable
	}
}

// WithCoreEndpoints sets the core endpoints to audit.
func WithCoreEndpoints(endpoints []string) Option {
	return func(m *AuditMiddleware) {
		m.CoreEndpoints = endpoints
	}
}

// NewAuditMiddleware creates a new AuditMiddleware with default values and applies options.
func NewAuditMiddleware(options ...Option) *AuditMiddleware {
	m := &AuditMiddleware{
		Logger:              NewAsyncAuditLogger(&DefaultAuditLogger{}, 100),
		MaskSensitiveFields: true,
		CustomMaskedFields:  []string{},
		MaxBodySizeToAudit:  1 << 20, // 1MB
		EnableOAuth21Checks: true,
		CoreEndpoints:       []string{"/authorize", "/token", "/register", "/revoke", "/metadata"},
	}
	for _, opt := range options {
		opt(m)
	}
	return m
}

// responseWriter wraps http.ResponseWriter to capture status and body.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

// WriteHeader captures the status code.
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Write captures the response body.
func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.body.Write(b)
	return rw.ResponseWriter.Write(b)
}

// Wrap implements Middleware by wrapping the next handler with audit logic.
func (m *AuditMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		traceID := extractTraceID(ctx)

		// Check if the request is for a core endpoint
		isCoreEndpoint := false
		for _, endpoint := range m.CoreEndpoints {
			if strings.HasSuffix(r.URL.Path, endpoint) {
				isCoreEndpoint = true
				break
			}
		}

		// Skip auditing if not a core endpoint
		if !isCoreEndpoint {
			next.ServeHTTP(w, r)
			return
		}

		// Audit the request
		reqEvent := AuditEvent{
			Timestamp: time.Now(),
			TraceID:   traceID,
			Type:      getRequestType(r.URL.Path),
			Details:   make(map[string]interface{}),
		}
		m.auditRequest(r, &reqEvent)
		if m.EnableOAuth21Checks {
			m.checkOAuth21Compliance(r, &reqEvent)
		}
		m.Logger.LogAuditEvent(ctx, reqEvent)

		// Read and restore request body
		var reqBody []byte
		if r.Body != nil && r.Method != http.MethodGet {
			limitedReader := io.LimitReader(r.Body, m.MaxBodySizeToAudit)
			reqBody, _ = io.ReadAll(limitedReader)
			r.Body = io.NopCloser(bytes.NewBuffer(reqBody))
			if len(reqBody) > 0 {
				m.parseAndMaskBody(r, string(reqBody), &reqEvent)
			}
			if int64(len(reqBody)) == m.MaxBodySizeToAudit {
				reqEvent.Details["BodyTruncated"] = true
			}
		}

		// Wrap response writer to capture response
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK, body: new(bytes.Buffer)}
		next.ServeHTTP(rw, r)

		// Audit the response
		respEvent := AuditEvent{
			Timestamp: time.Now(),
			TraceID:   traceID,
			Type:      "Response",
			Details:   make(map[string]interface{}),
		}
		m.auditResponse(rw, &reqEvent, &respEvent)
		m.Logger.LogAuditEvent(ctx, respEvent)
	})
}

// getRequestType determines the event type based on the endpoint.
func getRequestType(path string) string {
	switch {
	case strings.HasSuffix(path, "/authorize"):
		return "AuthorizeRequest"
	case strings.HasSuffix(path, "/token"):
		return "TokenRequest"
	case strings.HasSuffix(path, "/register"):
		return "RegisterRequest"
	case strings.HasSuffix(path, "/revoke"):
		return "RevokeRequest"
	case strings.HasSuffix(path, "/metadata"):
		return "MetadataRequest"
	default:
		return "UnknownRequest"
	}
}

// auditRequest populates the AuditEvent with request details.
func (m *AuditMiddleware) auditRequest(r *http.Request, event *AuditEvent) {
	event.Details["Method"] = r.Method
	event.Details["URL"] = r.URL.String()
	event.Details["QueryParams"] = r.URL.Query()
	event.Details["Headers"] = redactHeaders(r.Header)
}

// auditResponse populates the AuditEvent with response details and references request event for context.
func (m *AuditMiddleware) auditResponse(rw *responseWriter, reqEvent *AuditEvent, respEvent *AuditEvent) {
	respEvent.Details["StatusCode"] = rw.statusCode
	respEvent.Details["Headers"] = redactHeaders(rw.Header())
	respEvent.Details["RequestType"] = reqEvent.Type

	respBody := rw.body.Bytes()
	if len(respBody) > 0 {
		contentType := rw.Header().Get("Content-Type")
		if strings.Contains(contentType, "application/json") {
			var jsonBody map[string]interface{}
			if err := json.Unmarshal(respBody, &jsonBody); err == nil {
				if m.MaskSensitiveFields {
					m.maskSensitiveJSON(jsonBody)
				}
				respEvent.Details["Body"] = jsonBody
			} else {
				respEvent.Details["Body"] = string(respBody)
			}
		} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
			bodyParams := parseFormBody(string(respBody))
			if m.MaskSensitiveFields {
				m.maskSensitiveForm(bodyParams)
			}
			respEvent.Details["BodyParams"] = bodyParams
		} else {
			respEvent.Details["Body"] = string(respBody)
		}
		if int64(len(respBody)) == m.MaxBodySizeToAudit {
			respEvent.Details["BodyTruncated"] = true
		}
	}
}

// parseAndMaskBody parses and masks the request body based on content type.
func (m *AuditMiddleware) parseAndMaskBody(r *http.Request, bodyStr string, event *AuditEvent) {
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		bodyParams := parseFormBody(bodyStr)
		if m.MaskSensitiveFields {
			m.maskSensitiveForm(bodyParams)
		}
		event.Details["BodyParams"] = bodyParams
	} else if strings.Contains(contentType, "application/json") {
		var jsonBody map[string]interface{}
		if err := json.Unmarshal([]byte(bodyStr), &jsonBody); err == nil {
			if m.MaskSensitiveFields {
				m.maskSensitiveJSON(jsonBody)
			}
			event.Details["Body"] = jsonBody
		} else {
			event.Details["Body"] = string(bodyStr)
		}
	}
}

// parseFormBody parses urlencoded form into a map.
func parseFormBody(body string) map[string]string {
	params := make(map[string]string)
	for _, param := range strings.Split(body, "&") {
		parts := strings.SplitN(param, "=", 2)
		if len(parts) == 2 {
			params[parts[0]] = parts[1]
		}
	}
	return params
}

// maskSensitiveForm masks sensitive keys in form params.
func (m *AuditMiddleware) maskSensitiveForm(params map[string]string) {
	sensitive := append([]string{
		"client_secret", "password", "refresh_token", "access_token", "id_token", "code_verifier",
		"client_assertion",
	}, m.CustomMaskedFields...)
	for _, key := range sensitive {
		if _, ok := params[key]; ok {
			params[key] = "[MASKED]"
		}
	}
}

// maskSensitiveJSON masks sensitive keys in JSON body.
func (m *AuditMiddleware) maskSensitiveJSON(body map[string]interface{}) {
	sensitive := append([]string{
		"access_token", "refresh_token", "id_token", "client_secret", "code_verifier",
		"client_assertion",
	}, m.CustomMaskedFields...)
	for _, key := range sensitive {
		if _, ok := body[key]; ok {
			body[key] = "[MASKED]"
		}
	}
}

// checkOAuth21Compliance performs OAuth 2.1 compliance checks for each endpoint.
func (m *AuditMiddleware) checkOAuth21Compliance(r *http.Request, event *AuditEvent) {
	warnings := []string{}
	if m.EnableOAuth21Checks && r.URL.Scheme != "https" {
		warnings = append(warnings, "Non-HTTPS URL detected - OAuth 2.1 requires HTTPS")
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/authorize"):
		query := r.URL.Query()
		responseType := query.Get("response_type")
		if responseType == "token" || responseType == "id_token" {
			warnings = append(warnings, "Implicit flow (response_type=token or id_token) is deprecated in OAuth 2.1")
		}
		if responseType == "code" && query.Get("code_challenge") == "" {
			warnings = append(warnings, "Missing PKCE code_challenge - OAuth 2.1 requires PKCE for public clients")
		}
		redirectURI := query.Get("redirect_uri")
		if redirectURI != "" && !strings.HasPrefix(redirectURI, "https://") && !strings.HasPrefix(redirectURI, "http://localhost") {
			warnings = append(warnings, "Insecure redirect_uri - OAuth 2.1 requires HTTPS (except localhost)")
		}
	case strings.HasSuffix(r.URL.Path, "/token"):
		bodyParams, ok := event.Details["BodyParams"].(map[string]string)
		if !ok {
			bodyParams = parseFormBody(r.URL.RawQuery)
		}
		grantType := bodyParams["grant_type"]
		if grantType == "authorization_code" && bodyParams["code_verifier"] == "" {
			warnings = append(warnings, "Missing PKCE code_verifier - OAuth 2.1 requires PKCE for authorization_code grant")
		}
		if grantType == "password" {
			warnings = append(warnings, "Password grant is deprecated in OAuth 2.1")
		}
		if grantType == "client_credentials" && r.Header.Get("Authorization") == "" && bodyParams["client_secret"] == "" {
			warnings = append(warnings, "Missing client authentication - OAuth 2.1 recommends client_secret or private_key_jwt")
		}
	case strings.HasSuffix(r.URL.Path, "/register"):
		var jsonBody map[string]interface{}
		if body, ok := event.Details["Body"]; ok && r.Header.Get("Content-Type") == "application/json" {
			jsonBody, _ = body.(map[string]interface{})
		}
		if jsonBody != nil {
			if redirectURIs, ok := jsonBody["redirect_uris"].([]interface{}); ok {
				for _, uri := range redirectURIs {
					if uriStr, ok := uri.(string); ok && !strings.HasPrefix(uriStr, "https://") && !strings.HasPrefix(uriStr, "http://localhost") {
						warnings = append(warnings, "Insecure redirect_uri in client registration - OAuth 2.1 requires HTTPS")
					}
				}
			}
			if grantTypes, ok := jsonBody["grant_types"].([]interface{}); ok {
				for _, gt := range grantTypes {
					if gtStr, ok := gt.(string); ok && (gtStr == "implicit" || gtStr == "password") {
						warnings = append(warnings, "Deprecated grant_type in client registration: "+gtStr)
					}
				}
			}
		}
	case strings.HasSuffix(r.URL.Path, "/revoke"):
		bodyParams, ok := event.Details["BodyParams"].(map[string]string)
		if !ok {
			bodyParams = parseFormBody(r.URL.RawQuery)
		}
		if token := bodyParams["token"]; token == "" {
			warnings = append(warnings, "Missing token parameter in revocation request")
		}
	case strings.HasSuffix(r.URL.Path, "/metadata"):
		if r.Method != http.MethodGet {
			warnings = append(warnings, "Non-GET method used for /metadata - RFC 8414 recommends GET")
		}
	}
	if len(warnings) > 0 {
		event.Details["OAuth21Warnings"] = warnings
		event.Type = event.Type + "WithWarnings"
	}
}

// redactHeaders redacts sensitive headers.
func redactHeaders(headers http.Header) http.Header {
	redacted := make(http.Header)
	for k, v := range headers {
		lowerK := strings.ToLower(k)
		if lowerK == "authorization" || lowerK == "cookie" || lowerK == "x-api-key" {
			redacted[k] = []string{"[REDACTED]"}
		} else {
			redacted[k] = v
		}
	}
	return redacted
}

// extractTraceID extracts a trace ID from the context (placeholder for tracing integration).
func extractTraceID(ctx context.Context) string {
	if traceID, ok := ctx.Value("trace_id").(string); ok {
		return traceID
	}
	return ""
}
