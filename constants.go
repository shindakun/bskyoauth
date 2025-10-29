package bskyoauth

import "github.com/shindakun/bskyoauth/internal/validation"

// OAuth Application Types
const (
	// ApplicationTypeWeb indicates a web-based OAuth client.
	// Web clients must use HTTPS redirect URIs (except localhost for development).
	ApplicationTypeWeb = "web"

	// ApplicationTypeNative indicates a native/desktop OAuth client.
	// Native clients may use custom URI schemes or http://localhost redirect URIs.
	ApplicationTypeNative = "native"
)

// Context Keys for logging and correlation
const (
	// ContextKeyRequestID is the context key for request IDs
	ContextKeyRequestID contextKey = "request_id"

	// ContextKeySessionID is the context key for session IDs
	ContextKeySessionID contextKey = "session_id"
)

// Validation Limits
// Re-exported from internal/validation for convenience
const (
	// MaxPostTextLength is the maximum length for post text per AT Protocol spec (300 characters)
	MaxPostTextLength = validation.MaxPostTextLength

	// MaxHandleLength is the maximum length for handles per AT Protocol spec (253 characters)
	MaxHandleLength = validation.MaxHandleLength

	// MaxHandleSegmentLength is the maximum length for a single handle segment (63 characters)
	MaxHandleSegmentLength = validation.MaxHandleSegmentLength
)
