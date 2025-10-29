package bskyoauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// TestRateLimiterAllowsUnderLimit verifies that requests under the rate limit are allowed.
func TestRateLimiterAllowsUnderLimit(t *testing.T) {
	// Create a rate limiter: 10 requests per second, burst of 10
	rl := NewRateLimiter(10, 10)

	// Create a test handler that increments a counter
	callCount := 0
	handler := rl.Middleware(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})

	// Make 5 requests (under the burst limit)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()

		handler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: expected status 200, got %d", i, w.Code)
		}
	}

	if callCount != 5 {
		t.Errorf("Expected handler to be called 5 times, got %d", callCount)
	}
}

// TestRateLimiterBlocksOverLimit verifies that requests over the rate limit are blocked.
func TestRateLimiterBlocksOverLimit(t *testing.T) {
	// Create a rate limiter: 1 request per second, burst of 2
	rl := NewRateLimiter(1, 2)

	callCount := 0
	handler := rl.Middleware(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})

	// Make requests from the same IP
	ip := "192.168.1.1:12345"
	successCount := 0
	blockedCount := 0

	// First 2 should succeed (burst limit)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = ip
		w := httptest.NewRecorder()

		handler(w, req)

		if w.Code == http.StatusOK {
			successCount++
		}
	}

	// Next 3 should be rate limited
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = ip
		w := httptest.NewRecorder()

		handler(w, req)

		if w.Code == http.StatusTooManyRequests {
			blockedCount++
		}
	}

	if successCount != 2 {
		t.Errorf("Expected 2 successful requests, got %d", successCount)
	}

	if blockedCount != 3 {
		t.Errorf("Expected 3 blocked requests, got %d", blockedCount)
	}

	if callCount != 2 {
		t.Errorf("Expected handler to be called 2 times, got %d", callCount)
	}
}

// TestRateLimiterPerIP verifies that rate limits are applied per IP address.
func TestRateLimiterPerIP(t *testing.T) {
	// Create a rate limiter: 1 request per second, burst of 1
	rl := NewRateLimiter(1, 1)

	handler := rl.Middleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Request from IP 1 - should succeed
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "192.168.1.1:12345"
	w1 := httptest.NewRecorder()
	handler(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("First request from IP1: expected 200, got %d", w1.Code)
	}

	// Second request from IP 1 - should be blocked (burst exhausted)
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "192.168.1.1:12345"
	w2 := httptest.NewRecorder()
	handler(w2, req2)

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("Second request from IP1: expected 429, got %d", w2.Code)
	}

	// Request from IP 2 - should succeed (different IP, different limiter)
	req3 := httptest.NewRequest("GET", "/test", nil)
	req3.RemoteAddr = "192.168.1.2:12345"
	w3 := httptest.NewRecorder()
	handler(w3, req3)

	if w3.Code != http.StatusOK {
		t.Errorf("Request from IP2: expected 200, got %d", w3.Code)
	}
}

// TestRateLimiterXForwardedFor verifies that X-Forwarded-For header is respected.
func TestRateLimiterXForwardedFor(t *testing.T) {
	// Create a rate limiter: 1 request per second, burst of 1
	rl := NewRateLimiter(1, 1)

	handler := rl.Middleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// First request with X-Forwarded-For
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "10.0.0.1:12345" // Proxy IP
	req1.Header.Set("X-Forwarded-For", "203.0.113.1")
	w1 := httptest.NewRecorder()
	handler(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("First request: expected 200, got %d", w1.Code)
	}

	// Second request from same real IP (via X-Forwarded-For) should be blocked
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "10.0.0.1:12345"                // Same proxy IP
	req2.Header.Set("X-Forwarded-For", "203.0.113.1") // Same real IP
	w2 := httptest.NewRecorder()
	handler(w2, req2)

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("Second request from same X-Forwarded-For IP: expected 429, got %d", w2.Code)
	}

	// Request from different real IP should succeed
	req3 := httptest.NewRequest("GET", "/test", nil)
	req3.RemoteAddr = "10.0.0.1:12345"                // Same proxy IP
	req3.Header.Set("X-Forwarded-For", "203.0.113.2") // Different real IP
	w3 := httptest.NewRecorder()
	handler(w3, req3)

	if w3.Code != http.StatusOK {
		t.Errorf("Request from different X-Forwarded-For IP: expected 200, got %d", w3.Code)
	}
}

// TestRateLimiterXForwardedForChain verifies that only the first IP in X-Forwarded-For chain is used.
func TestRateLimiterXForwardedForChain(t *testing.T) {
	// Create a rate limiter: 1 request per second, burst of 1
	rl := NewRateLimiter(1, 1)

	handler := rl.Middleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// First request with X-Forwarded-For chain
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "10.0.0.1:12345"
	req1.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.5, 10.0.0.6")
	w1 := httptest.NewRecorder()
	handler(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("First request: expected 200, got %d", w1.Code)
	}

	// Second request with same first IP in chain should be blocked
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "10.0.0.1:12345"
	req2.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.7, 10.0.0.8")
	w2 := httptest.NewRecorder()
	handler(w2, req2)

	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("Second request with same first IP: expected 429, got %d", w2.Code)
	}
}

// TestRateLimiterCleanup verifies that the cleanup mechanism works.
func TestRateLimiterCleanup(t *testing.T) {
	rl := NewRateLimiter(10, 10)

	// Add many limiters to trigger cleanup
	for i := 0; i < 1500; i++ {
		rl.getLimiter(string(rune(i)))
	}

	// Verify we have many limiters
	rl.mu.RLock()
	initialCount := len(rl.limiters)
	rl.mu.RUnlock()

	if initialCount <= 1000 {
		t.Errorf("Expected more than 1000 limiters before cleanup, got %d", initialCount)
	}

	// Run cleanup - should clear the map when count exceeds 1000
	rl.Cleanup(10 * time.Minute)

	rl.mu.RLock()
	afterCleanup := len(rl.limiters)
	rl.mu.RUnlock()

	if afterCleanup != 0 {
		t.Errorf("Expected 0 limiters after cleanup, got %d", afterCleanup)
	}
}

// TestRateLimiterBurstRecovery verifies that burst capacity recovers over time.
func TestRateLimiterBurstRecovery(t *testing.T) {
	// Create a rate limiter: 10 requests per second, burst of 2
	rl := NewRateLimiter(10, 2)

	handler := rl.Middleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ip := "192.168.1.1:12345"

	// Use up the burst (2 requests)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = ip
		w := httptest.NewRecorder()
		handler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Burst request %d: expected 200, got %d", i, w.Code)
		}
	}

	// Next request should be blocked
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = ip
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Request after burst exhausted: expected 429, got %d", w.Code)
	}

	// Wait for capacity to recover (10 req/s = 100ms per request)
	time.Sleep(150 * time.Millisecond)

	// Should be able to make another request
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = ip
	w2 := httptest.NewRecorder()
	handler(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Request after recovery: expected 200, got %d", w2.Code)
	}
}

// TestRateLimiterInvalidRemoteAddr verifies handling of malformed RemoteAddr.
func TestRateLimiterInvalidRemoteAddr(t *testing.T) {
	rl := NewRateLimiter(10, 10)

	handler := rl.Middleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Request with invalid RemoteAddr format (no port)
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1"
	w := httptest.NewRecorder()

	handler(w, req)

	// Should still work, using full RemoteAddr as IP
	if w.Code != http.StatusOK {
		t.Errorf("Request with invalid RemoteAddr: expected 200, got %d", w.Code)
	}
}

// TestNewRateLimiter verifies rate limiter initialization.
func TestNewRateLimiter(t *testing.T) {
	rl := NewRateLimiter(5, 10)

	if rl.r != rate.Limit(5) {
		t.Errorf("Expected rate limit of 5, got %v", rl.r)
	}

	if rl.b != 10 {
		t.Errorf("Expected burst size of 10, got %d", rl.b)
	}

	if rl.limiters == nil {
		t.Error("Expected limiters map to be initialized")
	}

	if len(rl.limiters) != 0 {
		t.Errorf("Expected empty limiters map, got %d entries", len(rl.limiters))
	}
}

// TestRateLimiterConcurrency verifies thread-safe concurrent access.
func TestRateLimiterConcurrency(t *testing.T) {
	rl := NewRateLimiter(100, 100)

	handler := rl.Middleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Launch 10 goroutines making concurrent requests
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 10; j++ {
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "192.168.1.1:12345"
				w := httptest.NewRecorder()
				handler(w, req)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Test passes if no race conditions occur
	t.Log("Concurrent access test completed successfully")
}
