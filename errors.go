package bskyoauth

import (
	"context"
	"errors"
	"net"
	"os"
)

// IsTimeoutError checks if an error is a timeout error.
// Returns true for context deadline exceeded, network timeouts, and OS deadline exceeded.
func IsTimeoutError(err error) bool {
	if err == nil {
		return false
	}

	// Check for context deadline exceeded
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// Check for net.Error timeout
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// Check for os.ErrDeadlineExceeded
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}

	return false
}
