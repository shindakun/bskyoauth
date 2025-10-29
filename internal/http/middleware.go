package http

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter provides IP-based rate limiting for HTTP endpoints.
type RateLimiter struct {
	limiters     map[string]*rate.Limiter
	mu           sync.RWMutex
	r            rate.Limit
	b            int
	LoggerGetter func(*http.Request) Logger
}

// NewRateLimiter creates a new rate limiter.
// r is the rate (requests per second), b is the burst size.
// Example: NewRateLimiter(5, 10) allows 5 requests/second with burst of 10.
func NewRateLimiter(r rate.Limit, b int, loggerGetter func(*http.Request) Logger) *RateLimiter {
	return &RateLimiter{
		limiters:     make(map[string]*rate.Limiter),
		r:            r,
		b:            b,
		LoggerGetter: loggerGetter,
	}
}

// getLimiter returns the rate limiter for a given IP address.
func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rl.r, rl.b)
		rl.limiters[ip] = limiter
	}

	return limiter
}

// Middleware returns an HTTP middleware that applies rate limiting.
func (rl *RateLimiter) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := rl.LoggerGetter(r)

		// Extract IP address
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			// If we can't parse the IP, use the full RemoteAddr
			ip = r.RemoteAddr
		}

		// Check X-Forwarded-For header for proxied requests
		if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
			// Use the first IP in the X-Forwarded-For chain
			ip = forwardedFor
			for idx := 0; idx < len(ip); idx++ {
				if ip[idx] == ',' {
					ip = ip[:idx]
					break
				}
			}
		}

		// Get or create limiter for this IP
		limiter := rl.getLimiter(ip)

		// Check if request is allowed
		if !limiter.Allow() {
			logger.Warn("rate limit exceeded",
				"ip", ip,
				"path", r.URL.Path,
				"method", r.Method)
			http.Error(w, "Rate limit exceeded. Please try again later.", http.StatusTooManyRequests)
			return
		}

		logger.Info("rate limit check passed",
			"ip", ip,
			"path", r.URL.Path)

		// Call the next handler
		next(w, r)
	}
}

// Cleanup removes idle rate limiters to prevent memory leaks.
// Should be called periodically in a goroutine.
func (rl *RateLimiter) Cleanup(maxAge time.Duration, logger Logger) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// In a production system, you'd track last access time
	// For simplicity, we'll just clear the entire map periodically
	// This is safe because new limiters are created on demand
	if len(rl.limiters) > 1000 {
		logger.Info("rate limiter cleanup triggered",
			"limiter_count", len(rl.limiters),
			"threshold", 1000)
		rl.limiters = make(map[string]*rate.Limiter)
	}
}

// StartCleanup starts a background goroutine that periodically cleans up old limiters.
func (rl *RateLimiter) StartCleanup(interval, maxAge time.Duration, logger Logger) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			rl.Cleanup(maxAge, logger)
		}
	}()
}

// SecurityHeadersOptions allows customization of security headers.
// Use with SecurityHeadersMiddlewareWithOptions() for full control over CSP and other headers.
type SecurityHeadersOptions struct {
	// CSPConnectSrc specifies allowed origins for fetch/XHR/WebSocket.
	// Default includes Bluesky domains: 'self' https://*.bsky.social https://bsky.social
	CSPConnectSrc []string

	// CSPFormAction specifies allowed form submission targets.
	// Default includes Bluesky domains: 'self' https://*.bsky.social https://bsky.social
	CSPFormAction []string

	// CSPScriptSrc specifies allowed script sources.
	// Default localhost: 'self' 'unsafe-inline' 'unsafe-eval'
	// Default production: 'self'
	CSPScriptSrc []string

	// CSPStyleSrc specifies allowed style sources.
	// Default localhost: 'self' 'unsafe-inline'
	// Default production: 'self'
	CSPStyleSrc []string

	// CSPImgSrc specifies allowed image sources.
	// Default: 'self' data:
	CSPImgSrc []string

	// CSPDefaultSrc specifies the default policy.
	// Default: 'self'
	CSPDefaultSrc []string

	// AdditionalCSPDirectives allows adding custom CSP directives.
	// Example: map[string][]string{"media-src": {"'self'", "https://cdn.example.com"}}
	AdditionalCSPDirectives map[string][]string

	// CustomHeaders allows setting arbitrary HTTP headers.
	// Example: map[string]string{"X-Custom-Header": "value"}
	CustomHeaders map[string]string

	// DisableXFrameOptions disables X-Frame-Options header.
	// Default: false (X-Frame-Options: DENY is set)
	DisableXFrameOptions bool

	// DisableHSTS disables Strict-Transport-Security header even for HTTPS.
	// Default: false (HSTS enabled for HTTPS in production)
	DisableHSTS bool
}

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
//	handler := SecurityHeadersMiddleware()(mux)
//	http.ListenAndServe(":8080", handler)
func SecurityHeadersMiddleware() func(http.Handler) http.Handler {
	return SecurityHeadersMiddlewareWithOptions(nil)
}

// SecurityHeadersMiddlewareWithOptions returns middleware with custom security headers.
// Allows full customization of CSP policies and other security headers.
//
// Usage:
//
//	opts := &SecurityHeadersOptions{
//	    CSPConnectSrc: []string{"'self'", "https://api.example.com"},
//	    CustomHeaders: map[string]string{"X-Custom": "value"},
//	}
//	handler := SecurityHeadersMiddlewareWithOptions(opts)(mux)
func SecurityHeadersMiddlewareWithOptions(opts *SecurityHeadersOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			isLocalhost := isLocalhostRequest(r)
			isHTTPS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"

			applySecurityHeadersWithOptions(w, isLocalhost, isHTTPS, opts)
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

// applySecurityHeadersWithOptions applies custom security headers.
func applySecurityHeadersWithOptions(w http.ResponseWriter, isLocalhost, isHTTPS bool, opts *SecurityHeadersOptions) {
	// Get default options based on environment
	var defaultOpts *SecurityHeadersOptions
	if isLocalhost {
		defaultOpts = getDefaultLocalhostOptions()
	} else {
		defaultOpts = getDefaultProductionOptions()
	}

	// Merge user options with defaults
	if opts != nil {
		defaultOpts = mergeOptions(defaultOpts, opts)
	}

	// Apply standard headers unless disabled
	if !defaultOpts.DisableXFrameOptions {
		w.Header().Set("X-Frame-Options", "DENY")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

	// Build and apply CSP
	w.Header().Set("Content-Security-Policy", buildCSP(defaultOpts))

	// Apply HSTS if applicable
	if isHTTPS && !isLocalhost && !defaultOpts.DisableHSTS {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	}

	// Apply custom headers
	for key, value := range defaultOpts.CustomHeaders {
		w.Header().Set(key, value)
	}
}

// getDefaultLocalhostOptions returns default options for localhost.
func getDefaultLocalhostOptions() *SecurityHeadersOptions {
	return &SecurityHeadersOptions{
		CSPDefaultSrc: []string{"'self'"},
		CSPScriptSrc:  []string{"'self'", "'unsafe-inline'", "'unsafe-eval'"},
		CSPStyleSrc:   []string{"'self'", "'unsafe-inline'"},
		CSPImgSrc:     []string{"'self'", "data:"},
		CSPConnectSrc: []string{"'self'", "https://*.bsky.social", "https://bsky.social"},
		CSPFormAction: []string{"'self'", "https://*.bsky.social", "https://bsky.social"},
	}
}

// getDefaultProductionOptions returns default options for production.
func getDefaultProductionOptions() *SecurityHeadersOptions {
	return &SecurityHeadersOptions{
		CSPDefaultSrc: []string{"'self'"},
		CSPScriptSrc:  []string{"'self'"},
		CSPStyleSrc:   []string{"'self'"},
		CSPImgSrc:     []string{"'self'", "data:"},
		CSPConnectSrc: []string{"'self'", "https://*.bsky.social", "https://bsky.social"},
		CSPFormAction: []string{"'self'", "https://*.bsky.social", "https://bsky.social"},
		AdditionalCSPDirectives: map[string][]string{
			"frame-ancestors": {"'none'"},
			"base-uri":        {"'self'"},
		},
	}
}

// buildCSP constructs a CSP header string from options.
func buildCSP(opts *SecurityHeadersOptions) string {
	directives := make([]string, 0)

	if len(opts.CSPDefaultSrc) > 0 {
		directives = append(directives, "default-src "+strings.Join(opts.CSPDefaultSrc, " "))
	}
	if len(opts.CSPScriptSrc) > 0 {
		directives = append(directives, "script-src "+strings.Join(opts.CSPScriptSrc, " "))
	}
	if len(opts.CSPStyleSrc) > 0 {
		directives = append(directives, "style-src "+strings.Join(opts.CSPStyleSrc, " "))
	}
	if len(opts.CSPImgSrc) > 0 {
		directives = append(directives, "img-src "+strings.Join(opts.CSPImgSrc, " "))
	}
	if len(opts.CSPConnectSrc) > 0 {
		directives = append(directives, "connect-src "+strings.Join(opts.CSPConnectSrc, " "))
	}
	if len(opts.CSPFormAction) > 0 {
		directives = append(directives, "form-action "+strings.Join(opts.CSPFormAction, " "))
	}

	// Add additional directives
	for directive, values := range opts.AdditionalCSPDirectives {
		if len(values) > 0 {
			directives = append(directives, directive+" "+strings.Join(values, " "))
		}
	}

	return strings.Join(directives, "; ")
}

// mergeOptions merges user options into default options.
// User options override defaults when provided.
func mergeOptions(defaults, user *SecurityHeadersOptions) *SecurityHeadersOptions {
	merged := *defaults // Copy defaults

	if len(user.CSPDefaultSrc) > 0 {
		merged.CSPDefaultSrc = user.CSPDefaultSrc
	}
	if len(user.CSPScriptSrc) > 0 {
		merged.CSPScriptSrc = user.CSPScriptSrc
	}
	if len(user.CSPStyleSrc) > 0 {
		merged.CSPStyleSrc = user.CSPStyleSrc
	}
	if len(user.CSPImgSrc) > 0 {
		merged.CSPImgSrc = user.CSPImgSrc
	}
	if len(user.CSPConnectSrc) > 0 {
		merged.CSPConnectSrc = user.CSPConnectSrc
	}
	if len(user.CSPFormAction) > 0 {
		merged.CSPFormAction = user.CSPFormAction
	}

	// Merge additional directives
	if user.AdditionalCSPDirectives != nil {
		if merged.AdditionalCSPDirectives == nil {
			merged.AdditionalCSPDirectives = make(map[string][]string)
		}
		for k, v := range user.AdditionalCSPDirectives {
			merged.AdditionalCSPDirectives[k] = v
		}
	}

	// Apply flags
	merged.DisableXFrameOptions = user.DisableXFrameOptions
	merged.DisableHSTS = user.DisableHSTS

	// Custom headers
	if user.CustomHeaders != nil {
		merged.CustomHeaders = user.CustomHeaders
	}

	return &merged
}
