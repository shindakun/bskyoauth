package bskyoauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRateLimitEvasionBypass verifies rate limiting can't be bypassed
// via header manipulation.
func TestRateLimitEvasionBypass(t *testing.T) {
	t.Run("X-Forwarded-For manipulation blocked", func(t *testing.T) {
		limiter := NewRateLimiter(1, 2) // 1 req/sec, burst 2
		handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// First two requests should succeed (burst)
		for i := 0; i < 2; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("X-Forwarded-For", "1.2.3.4")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Errorf("Request %d should succeed, got status %d", i+1, w.Code)
			}
		}

		// Third request should be rate limited
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "1.2.3.4")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("Expected 429 Too Many Requests, got %d", w.Code)
		}

		// Different IP should still work
		req2 := httptest.NewRequest("GET", "/", nil)
		req2.Header.Set("X-Forwarded-For", "5.6.7.8")
		w2 := httptest.NewRecorder()
		handler.ServeHTTP(w2, req2)
		if w2.Code != http.StatusOK {
			t.Error("Different IP should not be rate limited")
		}
	})

	t.Run("IPv6 rate limiting works", func(t *testing.T) {
		limiter := NewRateLimiter(1, 1)
		handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// IPv6 address
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "[2001:db8::1]:1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Error("First IPv6 request should succeed")
		}

		// Second request should be limited
		req2 := httptest.NewRequest("GET", "/", nil)
		req2.RemoteAddr = "[2001:db8::1]:1234"
		w2 := httptest.NewRecorder()
		handler.ServeHTTP(w2, req2)
		if w2.Code != http.StatusTooManyRequests {
			t.Errorf("Second IPv6 request should be rate limited, got %d", w2.Code)
		}
	})
}

// TestRateLimitDistributedAttack simulates attacks from multiple IPs.
func TestRateLimitDistributedAttack(t *testing.T) {
	limiter := NewRateLimiter(1, 1)
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Simulate 10 different attackers
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0." + string(rune(i+'0')) + ":1234"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		// Each IP should get at least one request through
		if w.Code != http.StatusOK {
			t.Errorf("First request from IP %d should succeed", i)
		}

		// Second request from same IP should be limited
		req2 := httptest.NewRequest("GET", "/", nil)
		req2.RemoteAddr = "10.0.0." + string(rune(i+'0')) + ":1234"
		w2 := httptest.NewRecorder()
		handler.ServeHTTP(w2, req2)
		if w2.Code != http.StatusTooManyRequests {
			t.Errorf("Second request from IP %d should be limited", i)
		}
	}
}

// TestRateLimitEndpointSpecific tests that different endpoints can have
// different rate limits.
func TestRateLimitEndpointSpecific(t *testing.T) {
	// Strict limits for auth endpoints
	authLimiter := NewRateLimiter(1, 2)
	authHandler := authLimiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// More permissive for API endpoints
	apiLimiter := NewRateLimiter(10, 20)
	apiHandler := apiLimiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Auth endpoint should have strict limits
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/auth", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		w := httptest.NewRecorder()
		authHandler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Auth request %d should succeed (burst)", i+1)
		}
	}

	req := httptest.NewRequest("GET", "/auth", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	authHandler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Error("Auth endpoint should be rate limited after burst")
	}

	// API endpoint should allow more requests
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("GET", "/api/posts", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		w := httptest.NewRecorder()
		apiHandler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("API request %d should succeed (burst)", i+1)
		}
	}

	req = httptest.NewRequest("GET", "/api/posts", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w = httptest.NewRecorder()
	apiHandler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Error("API endpoint should eventually be rate limited")
	}
}
