package bskyoauth

import (
	"net/http"
	"strings"
)

// SecurityHeadersMiddleware returns middleware that adds security headers to responses.
// It automatically detects localhost from the HTTP request and relaxes the CSP policy
// for development while maintaining strict security for production.
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
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Detect if this is localhost
			isLocalhost := isLocalhostRequest(r)

			// Detect if this is HTTPS
			isHTTPS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"

			// Apply security headers
			applySecurityHeaders(w, isLocalhost, isHTTPS)

			next.ServeHTTP(w, r)
		})
	}
}

// isLocalhostRequest detects if the request is from localhost.
// Checks r.Host header for localhost, 127.0.0.1, [::1], and 0.0.0.0.
func isLocalhostRequest(r *http.Request) bool {
	host := r.Host

	// Handle IPv6 addresses in brackets
	if strings.HasPrefix(host, "[") {
		// Extract IPv6 address from [::1]:port format
		if idx := strings.Index(host, "]"); idx != -1 {
			host = host[:idx+1] // Keep the brackets
		}
		return host == "[::1]"
	}

	// Remove port if present for non-IPv6
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	return host == "localhost" ||
		host == "127.0.0.1" ||
		host == "0.0.0.0"
}

// applySecurityHeaders applies appropriate security headers based on environment.
func applySecurityHeaders(w http.ResponseWriter, isLocalhost, isHTTPS bool) {
	// Always apply these headers regardless of environment
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

	// Content-Security-Policy: relaxed for localhost, strict for production
	if isLocalhost {
		w.Header().Set("Content-Security-Policy", getLocalhostCSP())
	} else {
		w.Header().Set("Content-Security-Policy", getProductionCSP())
	}

	// Strict-Transport-Security: only for HTTPS in production (not localhost)
	// Setting HSTS on localhost would prevent HTTP access for local development
	if isHTTPS && !isLocalhost {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	}
}

// getLocalhostCSP returns a relaxed CSP policy for localhost development.
// Allows 'unsafe-inline' and 'unsafe-eval' for easy prototyping and hot-reloading.
func getLocalhostCSP() string {
	return "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"connect-src 'self'; " +
		"form-action 'self'"
}

// getProductionCSP returns a strict CSP policy for production deployments.
// Removes 'unsafe-inline' and 'unsafe-eval' to prevent XSS attacks.
// Adds frame-ancestors and base-uri for additional security.
func getProductionCSP() string {
	return "default-src 'self'; " +
		"script-src 'self'; " +
		"style-src 'self'; " +
		"img-src 'self' data:; " +
		"connect-src 'self'; " +
		"form-action 'self'; " +
		"frame-ancestors 'none'; " +
		"base-uri 'self'"
}
