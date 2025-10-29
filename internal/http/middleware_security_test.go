package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestIsLocalhostRequest_Localhost tests localhost detection
func TestIsLocalhostRequest_Localhost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"localhost:8080", true},
		{"127.0.0.1", true},
		{"127.0.0.1:8080", true},
		{"[::1]", true},
		{"[::1]:8080", true},
		{"0.0.0.0", true},
		{"0.0.0.0:8080", true},
		{"example.com", false},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host

			got := isLocalhostRequest(req)
			if got != tt.want {
				t.Errorf("isLocalhostRequest(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

// TestSecurityHeadersMiddleware_Localhost tests headers for localhost
func TestSecurityHeadersMiddleware_Localhost(t *testing.T) {
	handler := SecurityHeadersMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "localhost:8080"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Check all headers are present
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", w.Header().Get("X-Frame-Options"))
	}

	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", w.Header().Get("X-Content-Type-Options"))
	}

	if w.Header().Get("X-XSS-Protection") != "1; mode=block" {
		t.Errorf("X-XSS-Protection = %q, want '1; mode=block'", w.Header().Get("X-XSS-Protection"))
	}

	if w.Header().Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
		t.Errorf("Referrer-Policy = %q, want 'strict-origin-when-cross-origin'", w.Header().Get("Referrer-Policy"))
	}

	// Check CSP includes unsafe-inline and unsafe-eval for localhost
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "'unsafe-inline'") {
		t.Errorf("Localhost CSP should contain 'unsafe-inline', got: %q", csp)
	}
	if !strings.Contains(csp, "'unsafe-eval'") {
		t.Errorf("Localhost CSP should contain 'unsafe-eval', got: %q", csp)
	}

	// Check HSTS is NOT set for localhost
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Errorf("HSTS should not be set for localhost, got: %q", w.Header().Get("Strict-Transport-Security"))
	}
}

// TestSecurityHeadersMiddleware_ProductionHTTP tests headers for production HTTP
func TestSecurityHeadersMiddleware_ProductionHTTP(t *testing.T) {
	handler := SecurityHeadersMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Check CSP does NOT include unsafe-inline or unsafe-eval
	csp := w.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "'unsafe-inline'") {
		t.Errorf("Production CSP should NOT contain 'unsafe-inline', got: %q", csp)
	}
	if strings.Contains(csp, "'unsafe-eval'") {
		t.Errorf("Production CSP should NOT contain 'unsafe-eval', got: %q", csp)
	}

	// Check CSP includes frame-ancestors
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("Production CSP should contain 'frame-ancestors none', got: %q", csp)
	}

	// Check HSTS is NOT set for HTTP
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Errorf("HSTS should not be set for HTTP, got: %q", w.Header().Get("Strict-Transport-Security"))
	}
}

// TestSecurityHeadersMiddleware_ProductionHTTPS tests headers for production HTTPS
func TestSecurityHeadersMiddleware_ProductionHTTPS(t *testing.T) {
	handler := SecurityHeadersMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Check HSTS IS set for HTTPS in production
	hsts := w.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("HSTS should be set for HTTPS in production")
	}

	expectedHSTS := "max-age=31536000; includeSubDomains; preload"
	if hsts != expectedHSTS {
		t.Errorf("HSTS = %q, want %q", hsts, expectedHSTS)
	}

	// Verify strict CSP
	csp := w.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "'unsafe-inline'") {
		t.Errorf("Production CSP should NOT contain 'unsafe-inline', got: %q", csp)
	}
}

// TestGetLocalhostCSP tests localhost CSP policy
func TestGetLocalhostCSP(t *testing.T) {
	opts := getDefaultLocalhostOptions()
	csp := buildCSP(opts)

	// Check for key localhost features
	if !strings.Contains(csp, "'unsafe-inline'") {
		t.Error("Localhost CSP should contain 'unsafe-inline'")
	}

	if !strings.Contains(csp, "'unsafe-eval'") {
		t.Error("Localhost CSP should contain 'unsafe-eval'")
	}

	if !strings.Contains(csp, "script-src 'self' 'unsafe-inline' 'unsafe-eval'") {
		t.Error("Localhost CSP should allow unsafe-inline and unsafe-eval for scripts")
	}

	if !strings.Contains(csp, "style-src 'self' 'unsafe-inline'") {
		t.Error("Localhost CSP should allow unsafe-inline styles")
	}

	if !strings.Contains(csp, "default-src 'self'") {
		t.Error("Localhost CSP should have default-src 'self'")
	}
}

// TestGetProductionCSP tests production CSP policy
func TestGetProductionCSP(t *testing.T) {
	opts := getDefaultProductionOptions()
	csp := buildCSP(opts)

	// Check that unsafe directives are NOT present
	if strings.Contains(csp, "'unsafe-inline'") {
		t.Error("Production CSP should NOT contain 'unsafe-inline'")
	}

	if strings.Contains(csp, "'unsafe-eval'") {
		t.Error("Production CSP should NOT contain 'unsafe-eval'")
	}

	// Check for strict policies
	if !strings.Contains(csp, "script-src 'self'") {
		t.Error("Production CSP should have script-src 'self'")
	}

	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Error("Production CSP should have frame-ancestors 'none'")
	}

	if !strings.Contains(csp, "base-uri 'self'") {
		t.Error("Production CSP should have base-uri 'self'")
	}

	if !strings.Contains(csp, "default-src 'self'") {
		t.Error("Production CSP should have default-src 'self'")
	}
}

// TestSecurityHeaders_LocalhostHTTPS tests HSTS not set for localhost even with HTTPS
func TestSecurityHeaders_LocalhostHTTPS(t *testing.T) {
	handler := SecurityHeadersMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "localhost"
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// HSTS should NOT be set for localhost even with HTTPS
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Errorf("HSTS should not be set for localhost even with HTTPS, got: %q", w.Header().Get("Strict-Transport-Security"))
	}
}

// TestSecurityHeaders_AllHeadersPresent tests all required headers are present
func TestSecurityHeaders_AllHeadersPresent(t *testing.T) {
	handler := SecurityHeadersMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	requiredHeaders := []string{
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Content-Security-Policy",
		"Strict-Transport-Security",
	}

	for _, header := range requiredHeaders {
		if w.Header().Get(header) == "" {
			t.Errorf("Header %q should be present but was empty", header)
		}
	}
}

// TestSecurityHeaders_HandlerExecution tests that the wrapped handler is executed
func TestSecurityHeaders_HandlerExecution(t *testing.T) {
	executed := false
	handler := SecurityHeadersMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		executed = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "localhost"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !executed {
		t.Error("Wrapped handler should have been executed")
	}

	if w.Code != http.StatusOK {
		t.Errorf("Status code = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestSecurityHeaders_XFrameOptions tests X-Frame-Options is always DENY
func TestSecurityHeaders_XFrameOptions(t *testing.T) {
	tests := []struct {
		name string
		host string
	}{
		{"localhost", "localhost"},
		{"production", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := SecurityHeadersMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Header().Get("X-Frame-Options") != "DENY" {
				t.Errorf("X-Frame-Options should be DENY for %s, got: %q", tt.name, w.Header().Get("X-Frame-Options"))
			}
		})
	}
}

// TestSecurityHeaders_ContentTypeOptions tests X-Content-Type-Options is always nosniff
func TestSecurityHeaders_ContentTypeOptions(t *testing.T) {
	tests := []struct {
		name string
		host string
	}{
		{"localhost", "localhost"},
		{"production", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := SecurityHeadersMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Errorf("X-Content-Type-Options should be nosniff for %s, got: %q", tt.name, w.Header().Get("X-Content-Type-Options"))
			}
		})
	}
}

// TestBlueskyDomainsInCSP tests that Bluesky domains are included in CSP
func TestBlueskyDomainsInCSP(t *testing.T) {
	tests := []struct {
		name string
		host string
	}{
		{"localhost", "localhost:8080"},
		{"production", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := SecurityHeadersMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			csp := w.Header().Get("Content-Security-Policy")
			if !strings.Contains(csp, "https://*.bsky.social") {
				t.Errorf("CSP should contain https://*.bsky.social for %s, got: %q", tt.name, csp)
			}
			if !strings.Contains(csp, "https://bsky.social") {
				t.Errorf("CSP should contain https://bsky.social for %s, got: %q", tt.name, csp)
			}
		})
	}
}

// TestFormActionIncludesBluesky tests that form-action includes Bluesky domains
func TestFormActionIncludesBluesky(t *testing.T) {
	handler := SecurityHeadersMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action") {
		t.Fatalf("CSP should contain form-action directive, got: %q", csp)
	}
	if !strings.Contains(csp, "form-action 'self' https://*.bsky.social https://bsky.social") {
		t.Errorf("form-action should include Bluesky domains, got: %q", csp)
	}
}

// TestSecurityHeadersMiddlewareWithOptions tests custom options
func TestSecurityHeadersMiddlewareWithOptions(t *testing.T) {
	opts := &SecurityHeadersOptions{
		CSPConnectSrc: []string{"'self'", "https://api.example.com"},
		CustomHeaders: map[string]string{"X-Custom-Header": "test-value"},
	}

	handler := SecurityHeadersMiddlewareWithOptions(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Check custom connect-src
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "https://api.example.com") {
		t.Errorf("CSP should contain custom connect-src, got: %q", csp)
	}

	// Check custom header
	if w.Header().Get("X-Custom-Header") != "test-value" {
		t.Errorf("Expected X-Custom-Header: test-value, got: %q", w.Header().Get("X-Custom-Header"))
	}
}

// TestCustomCSPDirectives tests additional CSP directives
func TestCustomCSPDirectives(t *testing.T) {
	opts := &SecurityHeadersOptions{
		AdditionalCSPDirectives: map[string][]string{
			"media-src":  {"'self'", "https://cdn.example.com"},
			"worker-src": {"'self'"},
		},
	}

	handler := SecurityHeadersMiddlewareWithOptions(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "media-src 'self' https://cdn.example.com") {
		t.Errorf("CSP should contain custom media-src directive, got: %q", csp)
	}
	if !strings.Contains(csp, "worker-src 'self'") {
		t.Errorf("CSP should contain custom worker-src directive, got: %q", csp)
	}
}

// TestDisableXFrameOptions tests disabling X-Frame-Options
func TestDisableXFrameOptions(t *testing.T) {
	opts := &SecurityHeadersOptions{
		DisableXFrameOptions: true,
	}

	handler := SecurityHeadersMiddlewareWithOptions(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Header().Get("X-Frame-Options") != "" {
		t.Errorf("X-Frame-Options should be empty when disabled, got: %q", w.Header().Get("X-Frame-Options"))
	}
}

// TestDisableHSTS tests disabling HSTS
func TestDisableHSTS(t *testing.T) {
	opts := &SecurityHeadersOptions{
		DisableHSTS: true,
	}

	handler := SecurityHeadersMiddlewareWithOptions(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Errorf("HSTS should be empty when disabled, got: %q", w.Header().Get("Strict-Transport-Security"))
	}
}

// TestMergeOptions tests option merging logic
func TestMergeOptions(t *testing.T) {
	defaults := &SecurityHeadersOptions{
		CSPDefaultSrc: []string{"'self'"},
		CSPScriptSrc:  []string{"'self'"},
		CSPConnectSrc: []string{"'self'", "https://default.com"},
	}

	user := &SecurityHeadersOptions{
		CSPConnectSrc: []string{"'self'", "https://custom.com"},
		CustomHeaders: map[string]string{"X-Custom": "value"},
	}

	merged := mergeOptions(defaults, user)

	// User options should override
	if len(merged.CSPConnectSrc) != 2 || merged.CSPConnectSrc[1] != "https://custom.com" {
		t.Errorf("Expected custom connect-src, got: %v", merged.CSPConnectSrc)
	}

	// Default options should remain for non-overridden fields
	if len(merged.CSPDefaultSrc) != 1 || merged.CSPDefaultSrc[0] != "'self'" {
		t.Errorf("Expected default-src to remain, got: %v", merged.CSPDefaultSrc)
	}

	// Custom headers should be added
	if merged.CustomHeaders["X-Custom"] != "value" {
		t.Errorf("Expected custom header, got: %v", merged.CustomHeaders)
	}
}

// TestBuildCSP tests CSP string generation
func TestBuildCSP(t *testing.T) {
	opts := &SecurityHeadersOptions{
		CSPDefaultSrc: []string{"'self'"},
		CSPScriptSrc:  []string{"'self'", "'unsafe-inline'"},
		CSPConnectSrc: []string{"'self'", "https://api.example.com"},
		AdditionalCSPDirectives: map[string][]string{
			"frame-ancestors": {"'none'"},
		},
	}

	csp := buildCSP(opts)

	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP should contain default-src, got: %q", csp)
	}
	if !strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Errorf("CSP should contain script-src, got: %q", csp)
	}
	if !strings.Contains(csp, "connect-src 'self' https://api.example.com") {
		t.Errorf("CSP should contain connect-src, got: %q", csp)
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP should contain frame-ancestors, got: %q", csp)
	}
}

// TestLocalhostVsProductionCSP tests different CSP for localhost vs production
func TestLocalhostVsProductionCSP(t *testing.T) {
	handler := SecurityHeadersMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test localhost
	reqLocal := httptest.NewRequest("GET", "/", nil)
	reqLocal.Host = "localhost:8080"
	wLocal := httptest.NewRecorder()
	handler.ServeHTTP(wLocal, reqLocal)
	cspLocal := wLocal.Header().Get("Content-Security-Policy")

	// Test production
	reqProd := httptest.NewRequest("GET", "/", nil)
	reqProd.Host = "example.com"
	wProd := httptest.NewRecorder()
	handler.ServeHTTP(wProd, reqProd)
	cspProd := wProd.Header().Get("Content-Security-Policy")

	// Localhost should have unsafe directives
	if !strings.Contains(cspLocal, "'unsafe-inline'") {
		t.Errorf("Localhost CSP should contain 'unsafe-inline', got: %q", cspLocal)
	}
	if !strings.Contains(cspLocal, "'unsafe-eval'") {
		t.Errorf("Localhost CSP should contain 'unsafe-eval', got: %q", cspLocal)
	}

	// Production should NOT have unsafe directives in script-src
	// (except in other directives like style-src which we don't check here)
	if strings.Contains(cspProd, "script-src 'self' 'unsafe-inline'") || strings.Contains(cspProd, "script-src 'self' 'unsafe-eval'") {
		t.Errorf("Production CSP script-src should not contain unsafe directives, got: %q", cspProd)
	}

	// Production should have frame-ancestors
	if !strings.Contains(cspProd, "frame-ancestors") {
		t.Errorf("Production CSP should contain frame-ancestors, got: %q", cspProd)
	}

	// Localhost should NOT have frame-ancestors
	if strings.Contains(cspLocal, "frame-ancestors") {
		t.Errorf("Localhost CSP should not contain frame-ancestors, got: %q", cspLocal)
	}
}

// TestCustomFormAction tests custom form-action directive
func TestCustomFormAction(t *testing.T) {
	opts := &SecurityHeadersOptions{
		CSPFormAction: []string{"'self'", "https://forms.example.com"},
	}

	handler := SecurityHeadersMiddlewareWithOptions(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' https://forms.example.com") {
		t.Errorf("CSP should contain custom form-action, got: %q", csp)
	}
}
