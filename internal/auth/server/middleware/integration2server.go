
// WithAuditMiddleware applies AuditMiddleware to the server handler with specified options.
func WithAuditMiddleware(options ...middleware.Option) ServerOption {
	return func(s *http.Server) {
		// If no handler is set, use a default ServeMux
		if s.Handler == nil {
			s.Handler = http.NewServeMux()
		}
		// Create AuditMiddleware with options
		auditMiddleware := middleware.NewAuditMiddleware(options...)
		// Wrap the existing handler with AuditMiddleware
		s.Handler = auditMiddleware.Wrap(s.Handler)
	}
}


