package bskyoauth

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Logger is the package-level logger instance.
// By default, logs are discarded. Call SetLogger() to enable logging.
var Logger *slog.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))

// SetLogger sets the package-level logger.
// This should be called during application initialization to enable logging.
//
// Example:
//
//	// Text logging to stdout (development)
//	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
//	    Level: slog.LevelInfo,
//	})
//	bskyoauth.SetLogger(slog.New(handler))
//
//	// JSON logging to stdout (production)
//	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
//	    Level: slog.LevelError,
//	})
//	bskyoauth.SetLogger(slog.New(handler))
func SetLogger(logger *slog.Logger) {
	if logger != nil {
		Logger = logger
	}
}

// NewDefaultLogger creates a default logger with JSON output to stdout.
// Useful for quick setup without manual configuration.
func NewDefaultLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
}

// NewTextLogger creates a text logger for development/debugging.
func NewTextLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
}

// LogLevelFromEnv determines the appropriate log level based on environment.
// Checks BASE_URL to determine if running locally or in production.
// Returns Info level for localhost, Error level for production.
func LogLevelFromEnv(baseURL string) slog.Level {
	// Parse the base URL
	if baseURL == "" {
		return slog.LevelError // Default to production (Error level)
	}

	// Check if localhost
	if strings.Contains(baseURL, "localhost") ||
		strings.Contains(baseURL, "127.0.0.1") ||
		strings.Contains(baseURL, "[::1]") {
		return slog.LevelInfo // Development: Info level
	}

	return slog.LevelError // Production: Error level
}

// NewLoggerFromEnv creates a logger with appropriate settings based on environment.
// Uses BASE_URL to determine if running locally (text, Info) or production (JSON, Error).
//
// Example:
//
//	logger := bskyoauth.NewLoggerFromEnv(os.Getenv("BASE_URL"))
//	bskyoauth.SetLogger(logger)
func NewLoggerFromEnv(baseURL string) *slog.Logger {
	level := LogLevelFromEnv(baseURL)

	// Localhost: use text format for readability
	if strings.Contains(baseURL, "localhost") ||
		strings.Contains(baseURL, "127.0.0.1") ||
		strings.Contains(baseURL, "[::1]") {
		return NewTextLogger(level)
	}

	// Production: use JSON format for log aggregation
	return NewDefaultLogger(level)
}

// contextKey type for context values
type contextKey string

// WithRequestID adds a request ID to the context for correlation.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, ContextKeyRequestID, requestID)
}

// WithSessionID adds a session ID to the context for correlation.
func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, ContextKeySessionID, sessionID)
}

// LoggerFromContext returns a logger with context values attached.
// Extracts request_id and session_id from context if present.
func LoggerFromContext(ctx context.Context) *slog.Logger {
	logger := Logger

	if requestID, ok := ctx.Value(ContextKeyRequestID).(string); ok && requestID != "" {
		logger = logger.With("request_id", requestID)
	}

	if sessionID, ok := ctx.Value(ContextKeySessionID).(string); ok && sessionID != "" {
		logger = logger.With("session_id", sessionID)
	}

	return logger
}

// GenerateRequestID generates a unique request ID for correlation.
// Uses cryptographic randomness for uniqueness.
func GenerateRequestID() string {
	return GenerateSessionID() // Reuse session ID generation (already crypto-random)
}
