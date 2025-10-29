package bskyoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestSetLogger(t *testing.T) {
	// Save original logger
	originalLogger := Logger
	defer func() { Logger = originalLogger }()

	// Create test logger
	var buf bytes.Buffer
	testLogger := slog.New(slog.NewJSONHandler(&buf, nil))

	SetLogger(testLogger)

	if Logger != testLogger {
		t.Error("SetLogger did not update global logger")
	}

	// Test logging works
	Logger.Info("test message", "key", "value")

	if !strings.Contains(buf.String(), "test message") {
		t.Error("Logger did not write to buffer")
	}
}

func TestSetLoggerNil(t *testing.T) {
	originalLogger := Logger
	defer func() { Logger = originalLogger }()

	SetLogger(nil)

	// Logger should remain unchanged
	if Logger != originalLogger {
		t.Error("SetLogger(nil) should not change logger")
	}
}

func TestNewDefaultLogger(t *testing.T) {
	logger := NewDefaultLogger(slog.LevelInfo)
	if logger == nil {
		t.Fatal("NewDefaultLogger returned nil")
	}

	// Logger should be functional (won't test output to stdout)
}

func TestNewTextLogger(t *testing.T) {
	logger := NewTextLogger(slog.LevelDebug)
	if logger == nil {
		t.Fatal("NewTextLogger returned nil")
	}
}

func TestLogLevelFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		expected slog.Level
	}{
		{"localhost", "http://localhost:8181", slog.LevelInfo},
		{"localhost with https", "https://localhost:8181", slog.LevelInfo},
		{"127.0.0.1", "http://127.0.0.1:8181", slog.LevelInfo},
		{"IPv6 localhost", "http://[::1]:8181", slog.LevelInfo},
		{"production domain", "https://example.com", slog.LevelError},
		{"production subdomain", "https://app.example.com", slog.LevelError},
		{"empty string", "", slog.LevelError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := LogLevelFromEnv(tt.baseURL)
			if level != tt.expected {
				t.Errorf("LogLevelFromEnv(%q) = %v, want %v", tt.baseURL, level, tt.expected)
			}
		})
	}
}

func TestNewLoggerFromEnv(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
	}{
		{"localhost", "http://localhost:8181"},
		{"production", "https://example.com"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLoggerFromEnv(tt.baseURL)
			if logger == nil {
				t.Errorf("NewLoggerFromEnv(%q) returned nil", tt.baseURL)
			}

			// Verify logger works (won't test output format)
			logger.Info("test message")
		})
	}
}

func TestWithRequestID(t *testing.T) {
	ctx := context.Background()
	requestID := "test-request-123"

	ctx = WithRequestID(ctx, requestID)

	if got := ctx.Value(ContextKeyRequestID); got != requestID {
		t.Errorf("Expected request ID %q, got %v", requestID, got)
	}
}

func TestWithSessionID(t *testing.T) {
	ctx := context.Background()
	sessionID := "test-session-456"

	ctx = WithSessionID(ctx, sessionID)

	if got := ctx.Value(ContextKeySessionID); got != sessionID {
		t.Errorf("Expected session ID %q, got %v", sessionID, got)
	}
}

func TestLoggerFromContext(t *testing.T) {
	var buf bytes.Buffer
	testLogger := slog.New(slog.NewJSONHandler(&buf, nil))
	SetLogger(testLogger)
	defer func() { Logger = slog.New(slog.NewJSONHandler(io.Discard, nil)) }()

	ctx := context.Background()
	ctx = WithRequestID(ctx, "req-123")
	ctx = WithSessionID(ctx, "sess-456")

	logger := LoggerFromContext(ctx)
	logger.Info("test message")

	output := buf.String()
	if !strings.Contains(output, "req-123") {
		t.Error("Logger did not include request_id")
	}
	if !strings.Contains(output, "sess-456") {
		t.Error("Logger did not include session_id")
	}
}

func TestLoggerFromContextEmpty(t *testing.T) {
	var buf bytes.Buffer
	testLogger := slog.New(slog.NewJSONHandler(&buf, nil))
	SetLogger(testLogger)
	defer func() { Logger = slog.New(slog.NewJSONHandler(io.Discard, nil)) }()

	ctx := context.Background()

	logger := LoggerFromContext(ctx)
	logger.Info("test message")

	// Should not contain request_id or session_id keys
	output := buf.String()
	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	if _, ok := logEntry["request_id"]; ok {
		t.Error("Log entry should not contain request_id when not in context")
	}
	if _, ok := logEntry["session_id"]; ok {
		t.Error("Log entry should not contain session_id when not in context")
	}
}

func TestGenerateRequestID(t *testing.T) {
	id1 := GenerateRequestID()
	id2 := GenerateRequestID()

	if id1 == "" {
		t.Error("GenerateRequestID returned empty string")
	}
	if id1 == id2 {
		t.Error("GenerateRequestID returned duplicate IDs")
	}
	if len(id1) < 16 {
		t.Error("GenerateRequestID returned ID that seems too short")
	}
}
