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

	"github.com/google/uuid"
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

// LogAuditEvent implements AuditLogger using structured JSON logging.
func (l *DefaultAuditLogger) LogAuditEvent(ctx context.Context, event AuditEvent) {
	logEntry := map[string]interface{}{
		"timestamp": event.Timestamp.Format(time.RFC3339),
		"trace_id":  event.TraceID,
		"type":      event.Type,
		"details":   event.Details,
	}
	jsonLog, _ := json.Marshal(logEntry)
	log.Println(string(jsonLog))
}

// AsyncAuditLogger wraps an AuditLogger for asynchronous logging with batch processing.
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

// NewAsyncAuditLogger creates an async logger with batch processing.
func NewAsyncAuditLogger(inner AuditLogger, bufferSize int) *AsyncAuditLogger {
	if inner == nil {
		inner = &DefaultAuditLogger{}
	}
	al := &AsyncAuditLogger{
		inner: inner,
		ch:    make(chan AuditEventWithCtx, bufferSize),
	}
	al.wg.Add(1)
	al.startBatchProcessing()
	return al
}

// startBatchProcessing processes events in batches to reduce logging overhead.
func (al *AsyncAuditLogger) startBatchProcessing() {
	go func() {
		defer al.wg.Done()
		batch := make([]AuditEventWithCtx, 0, 10)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case e, ok := <-al.ch:
				if !ok {
					if len(batch) > 0 {
						al.processBatch(batch)
					}
					return
				}
				batch = append(batch, e)
				if len(batch) >= 10 {
					al.processBatch(batch)
					batch = batch[:0]
				}
			case <-ticker.C:
				if len(batch) > 0 {
					al.processBatch(batch)
					batch = batch[:0]
				}
			}
		}
	}()
}

func (al *AsyncAuditLogger) processBatch(batch []AuditEventWithCtx) {
	for _, e := range batch {
		al.inner.LogAuditEvent(e.Ctx, e.Event)
	}
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
	Type      string
	Details   map[string]interface{}
}

// AuditMiddleware is an http.Handler middleware for auditing OAuth 2.1 core endpoints.
type AuditMiddleware struct {
	Logger              AuditLogger
	SensitiveFields     []string
	MaxBodySizeToAudit  int64
	EnableOAuth21Checks bool
	complianceRules     []ComplianceRule
}

// ComplianceRule defines a rule for OAuth 2.1 compliance checks.
type ComplianceRule struct {
	Endpoint string
	Check    func(r *http.Request, event *AuditEvent) []string
}

// Option is a functional option for configuring AuditMiddleware.
type Option func(*AuditMiddleware)

// WithLogger sets the logger.
func WithLogger(logger AuditLogger) Option {
	return func(m *AuditMiddleware) {
		m.Logger = logger
	}
}

// WithSensitiveFields sets fields to mask.
func WithSensitiveFields(fields []string) Option {
	return func(m *AuditMiddleware) {
		m.SensitiveFields = fields
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

// NewAuditMiddleware creates a new AuditMiddleware with default values and applies options.
func NewAuditMiddleware(options ...Option) *AuditMiddleware {
	m := &AuditMiddleware{
		Logger:              NewAsyncAuditLogger(&DefaultAuditLogger{}, 100),
		SensitiveFields:     []string{"client_secret", "password", "refresh_token", "access_token", "id_token", "code_verifier", "client_assertion"},
		MaxBodySizeToAudit:  1 << 20, // 1MB
		EnableOAuth21Checks: true,
	}
	for _, opt := range options {
		opt(m)
	}
	m.initComplianceRules()
	return m
}

// initComplianceRules initializes OAuth 2.1 compliance rules.
func (m *AuditMiddleware) initComplianceRules() {
	m.complianceRules = []ComplianceRule{
		{
			Endpoint: "/authorize",
			Check: func(r *http.Request, event *AuditEvent) []string {
				warnings := []string{}
				if r.URL.Scheme != "https" {
					warnings = append(warnings, "Non-HTTPS URL detected - OAuth 2.1 requires HTTPS")
				}
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
				return warnings
			},
		},
		{
			Endpoint: "/token",
			Check: func(r *http.Request, event *AuditEvent) []string {
				warnings := []string{}
				if r.URL.Scheme != "https" {
					warnings = append(warnings, "Non-HTTPS URL detected - OAuth 2.1 requires HTTPS")
				}
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
				return warnings
			},
		},
		{
			Endpoint: "/register",
			Check: func(r *http.Request, event *AuditEvent) []string {
				warnings := []string{}
				if r.URL.Scheme != "https" {
					warnings = append(warnings, "Non-HTTPS URL detected - OAuth 2.1 requires HTTPS")
				}
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
				return warnings
			},
		},
		{
			Endpoint: "/revoke",
			Check: func(r *http.Request, event *AuditEvent) []string {
				warnings := []string{}
				if r.URL.Scheme != "https" {
					warnings = append(warnings, "Non-HTTPS URL detected - OAuth 2.1 requires HTTPS")
				}
				bodyParams, ok := event.Details["BodyParams"].(map[string]string)
				if !ok {
					bodyParams = parseFormBody(r.URL.RawQuery)
				}
				if token := bodyParams["token"]; token == "" {
					warnings = append(warnings, "Missing token parameter in revocation request")
				}
				return warnings
			},
		},
		{
			Endpoint: "/metadata",
			Check: func(r *http.Request, event *AuditEvent) []string {
				warnings := []string{}
				if r.URL.Scheme != "https" {
					warnings = append(warnings, "Non-HTTPS URL detected - OAuth 2.1 requires HTTPS")
				}
				if r.Method != http.MethodGet {
					warnings = append(warnings, "Non-GET method used for /metadata - RFC 8414 recommends GET")
				}
				return warnings
			},
		},
	}
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

var bufferPool = sync.Pool{
	New: func() interface{} { return new(bytes.Buffer) },
}

// Wrap implements Middleware by wrapping the next handler with audit logic.
func (m *AuditMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		traceID := extractTraceID(ctx)
		coreEndpoints := []string{"/authorize", "/token", "/register", "/revoke", "/metadata"}

		// Check if the request is for a core endpoint
		isCoreEndpoint := false
		for _, endpoint := range coreEndpoints {
			if strings.HasSuffix(r.URL.Path, endpoint) {
				isCoreEndpoint = true
				break
			}
		}
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

		// Wrap response writer
		buf := bufferPool.Get().(*bytes.Buffer)
		defer bufferPool.Put(buf)
		buf.Reset()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK, body: buf}
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

// auditRequest populates the AuditEvent with request details.
func (m *AuditMiddleware) auditRequest(r *http.Request, event *AuditEvent) {
	event.Details["Method"] = r.Method
	event.Details["URL"] = r.URL.String()
	event.Details["QueryParams"] = r.URL.Query()
	event.Details["Headers"] = redactHeaders(r.Header)
	if r.Body != nil && r.Method != http.MethodGet {
		m.parseRequestBody(r, event)
	}
}

// parseRequestBody parses and masks the request body.
func (m *AuditMiddleware) parseRequestBody(r *http.Request, event *AuditEvent) {
	contentType := r.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") && !strings.Contains(contentType, "application/x-www-form-urlencoded") {
		event.Details["Body"] = "[SKIPPED: Unsupported Content-Type]"
		return
	}

	limitedReader := io.LimitReader(r.Body, m.MaxBodySizeToAudit)
	reqBody, _ := io.ReadAll(limitedReader)
	r.Body = io.NopCloser(bytes.NewBuffer(reqBody))
	if len(reqBody) > 0 {
		m.parseAndMaskBody(r, string(reqBody), event)
	}
	if int64(len(reqBody)) == m.MaxBodySizeToAudit {
		event.Details["BodyTruncated"] = true
	}
}

// auditResponse populates the AuditEvent with response details.
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
				if len(m.SensitiveFields) > 0 {
					m.maskSensitiveJSON(jsonBody)
				}
				respEvent.Details["Body"] = jsonBody
			} else {
				respEvent.Details["ParseError"] = err.Error()
				respEvent.Details["Body"] = string(respBody)
			}
		} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
			bodyParams := parseFormBody(string(respBody))
			if len(m.SensitiveFields) > 0 {
				m.maskSensitiveForm(bodyParams)
			}
			respEvent.Details["BodyParams"] = bodyParams
		} else {
			respEvent.Details["Body"] = "[SKIPPED: Unsupported Content-Type]"
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
		if len(m.SensitiveFields) > 0 {
			m.maskSensitiveForm(bodyParams)
		}
		event.Details["BodyParams"] = bodyParams
	} else if strings.Contains(contentType, "application/json") {
		var jsonBody map[string]interface{}
		if err := json.Unmarshal([]byte(bodyStr), &jsonBody); err == nil {
			if len(m.SensitiveFields) > 0 {
				m.maskSensitiveJSON(jsonBody)
			}
			event.Details["Body"] = jsonBody
		} else {
			event.Details["ParseError"] = err.Error()
			event.Details["Body"] = bodyStr
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
	sensitive := make(map[string]struct{}, len(m.SensitiveFields))
	for _, key := range m.SensitiveFields {
		sensitive[key] = struct{}{}
	}
	for key := range params {
		if _, ok := sensitive[key]; ok {
			params[key] = "[MASKED]"
		}
	}
}

// maskSensitiveJSON masks sensitive keys in JSON body.
func (m *AuditMiddleware) maskSensitiveJSON(body map[string]interface{}) {
	sensitive := make(map[string]struct{}, len(m.SensitiveFields))
	for _, key := range m.SensitiveFields {
		sensitive[key] = struct{}{}
	}
	for key := range body {
		if _, ok := sensitive[key]; ok {
			body[key] = "[MASKED]"
		}
	}
}

// checkOAuth21Compliance performs OAuth 2.1 compliance checks.
func (m *AuditMiddleware) checkOAuth21Compliance(r *http.Request, event *AuditEvent) {
	for _, rule := range m.complianceRules {
		if strings.HasSuffix(r.URL.Path, rule.Endpoint) {
			warnings := rule.Check(r, event)
			if len(warnings) > 0 {
				event.Details["OAuth21Warnings"] = warnings
				event.Type = event.Type + "WithWarnings"
			}
		}
	}
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

// extractTraceID extracts a trace ID from the context or generates a new one.
func extractTraceID(ctx context.Context) string {
	if traceID, ok := ctx.Value("trace_id").(string); ok && traceID != "" {
		return traceID
	}
	return uuid.New().String()
}
