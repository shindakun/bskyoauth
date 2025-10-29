package bskyoauth

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
	csp := getLocalhostCSP()

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
	csp := getProductionCSP()

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
