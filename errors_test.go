package bskyoauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// mockTimeoutError is a mock implementation of net.Error with Timeout() returning true
type mockTimeoutError struct {
	error
}

func (e *mockTimeoutError) Timeout() bool   { return true }
func (e *mockTimeoutError) Temporary() bool { return false }

func TestIsTimeoutError_WrappedContextDeadlineExceeded(t *testing.T) {
	err := fmt.Errorf("wrapped error: %w", context.DeadlineExceeded)
	if !IsTimeoutError(err) {
		t.Error("IsTimeoutError should return true for wrapped context.DeadlineExceeded")
	}
}

func TestIsTimeoutError_NetError(t *testing.T) {
	err := &mockTimeoutError{error: errors.New("network timeout")}
	if !IsTimeoutError(err) {
		t.Error("IsTimeoutError should return true for net.Error with Timeout() = true")
	}
}

func TestIsTimeoutError_WrappedNetError(t *testing.T) {
	netErr := &mockTimeoutError{error: errors.New("network timeout")}
	err := fmt.Errorf("wrapped: %w", netErr)
	if !IsTimeoutError(err) {
		t.Error("IsTimeoutError should return true for wrapped net.Error timeout")
	}
}

func TestIsTimeoutError_OSDeadlineExceeded(t *testing.T) {
	err := os.ErrDeadlineExceeded
	if !IsTimeoutError(err) {
		t.Error("IsTimeoutError should return true for os.ErrDeadlineExceeded")
	}
}

func TestIsTimeoutError_WrappedOSDeadlineExceeded(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", os.ErrDeadlineExceeded)
	if !IsTimeoutError(err) {
		t.Error("IsTimeoutError should return true for wrapped os.ErrDeadlineExceeded")
	}
}

func TestIsTimeoutError_WrappedNonTimeoutError(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", errors.New("some other error"))
	if IsTimeoutError(err) {
		t.Error("IsTimeoutError should return false for wrapped non-timeout error")
	}
}

func TestIsTimeoutError_ContextCanceled(t *testing.T) {
	// context.Canceled is different from context.DeadlineExceeded
	err := context.Canceled
	if IsTimeoutError(err) {
		t.Error("IsTimeoutError should return false for context.Canceled (not a timeout)")
	}
}

func TestIsTimeoutError_RealDialTimeout(t *testing.T) {
	// Create a real timeout error by attempting to connect to a non-routable IP
	// with a very short timeout
	dialer := net.Dialer{
		Timeout: 1 * time.Nanosecond, // Extremely short timeout
	}
	_, err := dialer.Dial("tcp", "192.0.2.1:80") // 192.0.2.0/24 is reserved for documentation

	if err == nil {
		t.Skip("Expected dial to fail with timeout")
	}

	// This should be a real timeout error
	if !IsTimeoutError(err) {
		t.Errorf("IsTimeoutError should return true for real dial timeout, got error: %v", err)
	}
}
