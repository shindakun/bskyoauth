package bskyoauth

import (
	"net/http"
	"time"

	"golang.org/x/time/rate"

	internalhttp "github.com/shindakun/bskyoauth/internal/http"
)

// RateLimiter provides IP-based rate limiting for HTTP endpoints.
type RateLimiter struct {
	limiter *internalhttp.RateLimiter
}

// NewRateLimiter creates a new rate limiter.
// r is the rate (requests per second), b is the burst size.
// Example: NewRateLimiter(5, 10) allows 5 requests/second with burst of 10.
func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	loggerGetter := func(req *http.Request) internalhttp.Logger {
		return LoggerFromContext(req.Context())
	}
	return &RateLimiter{
		limiter: internalhttp.NewRateLimiter(r, b, loggerGetter),
	}
}

// Middleware returns an HTTP middleware that applies rate limiting.
func (rl *RateLimiter) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return rl.limiter.Middleware(next)
}

// Cleanup removes idle rate limiters to prevent memory leaks.
// Should be called periodically in a goroutine.
func (rl *RateLimiter) Cleanup(maxAge time.Duration) {
	rl.limiter.Cleanup(maxAge, Logger)
}

// StartCleanup starts a background goroutine that periodically cleans up old limiters.
func (rl *RateLimiter) StartCleanup(interval, maxAge time.Duration) {
	rl.limiter.StartCleanup(interval, maxAge, Logger)
}
