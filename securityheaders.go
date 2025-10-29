package bskyoauth

import (
	"net/http"

	internalhttp "github.com/shindakun/bskyoauth/internal/http"
)

// SecurityHeadersOptions allows customization of security headers.
// Re-exported from internal/http for backward compatibility.
type SecurityHeadersOptions = internalhttp.SecurityHeadersOptions

// SecurityHeadersMiddleware returns middleware that adds security headers to responses.
// It automatically detects localhost from the HTTP request and relaxes the CSP policy
// for development while maintaining strict security for production.
//
// Default CSP includes Bluesky domains in connect-src and form-action to enable:
//   - HTML forms to POST directly to Bluesky API endpoints
//   - Client-side JavaScript to make API calls to Bluesky servers
//
// Localhost detection checks r.Host for:
//   - localhost
//   - 127.0.0.1
//   - [::1]
//   - 0.0.0.0
//
// HTTPS detection checks:
//   - r.TLS != nil (direct HTTPS)
//   - X-Forwarded-Proto: https (reverse proxy)
//
// Headers applied:
//   - Content-Security-Policy (relaxed for localhost, strict for production)
//   - X-Frame-Options: DENY
//   - X-Content-Type-Options: nosniff
//   - X-XSS-Protection: 1; mode=block
//   - Referrer-Policy: strict-origin-when-cross-origin
//   - Strict-Transport-Security (HTTPS production only, not localhost)
//
// Usage:
//
//	mux := http.NewServeMux()
//	// ... set up handlers ...
//	handler := bskyoauth.SecurityHeadersMiddleware()(mux)
//	http.ListenAndServe(":8080", handler)
func SecurityHeadersMiddleware() func(http.Handler) http.Handler {
	return internalhttp.SecurityHeadersMiddleware()
}

// SecurityHeadersMiddlewareWithOptions returns middleware with custom security headers.
// Allows full customization of CSP policies and other security headers.
//
// Usage:
//
//	opts := &bskyoauth.SecurityHeadersOptions{
//	    CSPConnectSrc: []string{"'self'", "https://api.example.com"},
//	    CustomHeaders: map[string]string{"X-Custom": "value"},
//	}
//	handler := bskyoauth.SecurityHeadersMiddlewareWithOptions(opts)(mux)
func SecurityHeadersMiddlewareWithOptions(opts *SecurityHeadersOptions) func(http.Handler) http.Handler {
	return internalhttp.SecurityHeadersMiddlewareWithOptions(opts)
}
