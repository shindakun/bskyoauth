package bskyoauth

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter provides IP-based rate limiting for HTTP endpoints.
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	r        rate.Limit
	b        int
}

// NewRateLimiter creates a new rate limiter.
// r is the rate (requests per second), b is the burst size.
// Example: NewRateLimiter(5, 10) allows 5 requests/second with burst of 10.
func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		r:        r,
		b:        b,
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
		logger := LoggerFromContext(r.Context())

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

		logger.Debug("rate limit check passed",
			"ip", ip,
			"path", r.URL.Path)

		// Call the next handler
		next(w, r)
	}
}

// Cleanup removes idle rate limiters to prevent memory leaks.
// Should be called periodically in a goroutine.
func (rl *RateLimiter) Cleanup(maxAge time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// In a production system, you'd track last access time
	// For simplicity, we'll just clear the entire map periodically
	// This is safe because new limiters are created on demand
	if len(rl.limiters) > 1000 {
		Logger.Info("rate limiter cleanup triggered",
			"limiter_count", len(rl.limiters),
			"threshold", 1000)
		rl.limiters = make(map[string]*rate.Limiter)
	}
}

// StartCleanup starts a background goroutine that periodically cleans up old limiters.
func (rl *RateLimiter) StartCleanup(interval, maxAge time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			rl.Cleanup(maxAge)
		}
	}()
}
