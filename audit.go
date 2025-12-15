package bskyoauth

import (
	"context"
	"time"
)

// AuditEvent represents a security-relevant action in the system.
// Audit events provide a tamper-evident trail of sensitive operations
// for compliance, security monitoring, and forensic analysis.
type AuditEvent struct {
	// Timestamp when the event occurred (UTC)
	Timestamp time.Time `json:"timestamp"`

	// EventType categorizes the event (e.g., "auth.start", "session.created")
	// Use predefined constants (AuditEvent*) for consistency
	EventType string `json:"event_type"`

	// Actor is the DID of the user performing the action
	// Empty for unauthenticated actions (e.g., login attempts)
	Actor string `json:"actor,omitempty"`

	// Action describes what happened (e.g., "start_oauth_flow", "create_post")
	Action string `json:"action"`

	// Resource identifies what was acted upon
	// Examples: handle, AT URI, record key
	Resource string `json:"resource,omitempty"`

	// Result indicates success or failure ("success", "failure")
	Result string `json:"result"`

	// Error contains error details if Result == "failure"
	Error string `json:"error,omitempty"`

	// Metadata contains additional context (IP address, user agent, etc.)
	// Use this for compliance-specific data that doesn't fit standard fields
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// RequestID for correlation with application logs
	// Automatically populated from context if available
	RequestID string `json:"request_id,omitempty"`

	// SessionID for correlation with user sessions
	// Automatically populated from context if available
	SessionID string `json:"session_id,omitempty"`
}

// AuditLogger defines the interface for audit trail implementations.
// Implementations should be thread-safe and handle errors gracefully.
//
// Common implementations:
// - File-based: FileAuditLogger, RotatingFileAuditLogger
// - Database: PostgreSQL, MySQL, MongoDB
// - Cloud: AWS CloudWatch, Google Cloud Logging, Azure Monitor
// - SIEM: Splunk, ELK Stack, Datadog
type AuditLogger interface {
	// Log records an audit event
	// Returns error if the event cannot be persisted
	// Implementations should not panic
	Log(ctx context.Context, event AuditEvent) error
}

// NoOpAuditLogger is the default audit logger that does nothing.
// This is the safe default - users must explicitly enable audit logging.
type NoOpAuditLogger struct{}

// Log implements AuditLogger interface (no-op)
func (n *NoOpAuditLogger) Log(ctx context.Context, event AuditEvent) error {
	return nil
}

// Standard audit event types for consistent categorization
const (
	// Authentication events
	AuditEventAuthStart    = "auth.start"    // OAuth flow initiated
	AuditEventAuthSuccess  = "auth.success"  // OAuth flow completed successfully
	AuditEventAuthFailure  = "auth.failure"  // OAuth flow failed
	AuditEventAuthCallback = "auth.callback" // OAuth callback received

	// Session events
	AuditEventSessionCreated = "session.created" // New session created
	AuditEventSessionDeleted = "session.deleted" // Session explicitly deleted
	AuditEventSessionExpired = "session.expired" // Session expired (TTL)
	AuditEventSessionRefresh = "session.refresh" // Token refresh performed

	// API operation events
	AuditEventPostCreate   = "api.post.create"   // Post created
	AuditEventPostDelete   = "api.post.delete"   // Post deleted
	AuditEventRecordCreate = "api.record.create" // Custom record created
	AuditEventRecordDelete = "api.record.delete" // Custom record deleted
	AuditEventRecordRead   = "api.record.read"   // Custom record retrieved
	AuditEventRecordPut    = "api.record.put"    // Custom record created or updated
	AuditEventRecordList   = "api.record.list"   // Records listed

	// Security events
	AuditEventSecurityIssuerMismatch = "security.issuer_mismatch" // Issuer validation failed
	AuditEventSecurityInvalidState   = "security.invalid_state"   // Invalid OAuth state
	AuditEventSecurityRateLimit      = "security.rate_limit"      // Rate limit exceeded
)

// Standard result values
const (
	AuditResultSuccess = "success"
	AuditResultFailure = "failure"
)

// Package-level audit logger (default: no-op)
var auditLogger AuditLogger = &NoOpAuditLogger{}

// SetAuditLogger configures the audit logger for the package.
// Set to nil to disable audit logging (reverts to no-op).
//
// Example:
//
//	auditLogger, _ := bskyoauth.NewRotatingFileAuditLogger("/var/log/myapp/audit")
//	bskyoauth.SetAuditLogger(auditLogger)
func SetAuditLogger(logger AuditLogger) {
	if logger != nil {
		auditLogger = logger
	} else {
		auditLogger = &NoOpAuditLogger{}
	}
}

// GetAuditLogger returns the current audit logger.
// Useful for testing or wrapping the logger.
func GetAuditLogger() AuditLogger {
	return auditLogger
}

// LogAuditEvent is a convenience function to log an audit event.
// Automatically enriches the event with context data (timestamp, request ID, session ID).
//
// Example:
//
//	bskyoauth.LogAuditEvent(ctx, bskyoauth.AuditEvent{
//	    EventType: bskyoauth.AuditEventPostCreate,
//	    Actor:     session.DID,
//	    Action:    "create_post",
//	    Result:    bskyoauth.AuditResultSuccess,
//	})
func LogAuditEvent(ctx context.Context, event AuditEvent) error {
	// Enrich event with timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Enrich with request ID from context
	if requestID, ok := ctx.Value(ContextKeyRequestID).(string); ok && requestID != "" {
		event.RequestID = requestID
	}

	// Enrich with session ID from context
	if sessionID, ok := ctx.Value(ContextKeySessionID).(string); ok && sessionID != "" {
		event.SessionID = sessionID
	}

	return auditLogger.Log(ctx, event)
}
