package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var (
	// ErrSessionNotFound is returned when a session ID doesn't exist
	ErrSessionNotFound = errors.New("session not found")

	// ErrInvalidSession is returned when a session is invalid or expired
	ErrInvalidSession = errors.New("invalid session")
)

const (
	// DefaultSessionTTL is the default time-to-live for sessions (30 days, matches cookie MaxAge)
	DefaultSessionTTL = 30 * 24 * time.Hour

	// DefaultSessionCleanupInterval is how often the session cleanup goroutine runs
	DefaultSessionCleanupInterval = 5 * time.Minute
)

// Session represents an authenticated user session.
// This is a local copy to avoid import cycles. The public Session type is in the root package.
type Session interface{}

// Logger interface for session logging
type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

var defaultLogger Logger = &noopLogger{}

// SetLogger sets the logger for session operations
func SetLogger(l Logger) {
	defaultLogger = l
}

type noopLogger struct{}

func (n *noopLogger) Debug(msg string, args ...interface{}) {}
func (n *noopLogger) Info(msg string, args ...interface{})  {}
func (n *noopLogger) Warn(msg string, args ...interface{})  {}
func (n *noopLogger) Error(msg string, args ...interface{}) {}

// sessionEntry wraps a session with expiration tracking.
type sessionEntry struct {
	session   Session
	expiresAt time.Time
}

// MemoryStore is an in-memory implementation of SessionStore with automatic expiration.
type MemoryStore struct {
	sessions        map[string]*sessionEntry
	mu              sync.RWMutex
	ttl             time.Duration
	cleanupInterval time.Duration
	stopCh          chan struct{}
	stopped         bool
}

// NewMemoryStore creates a new in-memory session store with default TTL (30 days).
// Sessions automatically expire and are cleaned up every 5 minutes.
func NewMemoryStore() *MemoryStore {
	return NewMemoryStoreWithTTL(DefaultSessionTTL, DefaultSessionCleanupInterval)
}

// NewMemoryStoreWithTTL creates a new in-memory session store with custom TTL and cleanup interval.
// ttl: how long sessions remain valid before expiring
// cleanupInterval: how often the cleanup goroutine runs to remove expired sessions
func NewMemoryStoreWithTTL(ttl, cleanupInterval time.Duration) *MemoryStore {
	store := &MemoryStore{
		sessions:        make(map[string]*sessionEntry),
		ttl:             ttl,
		cleanupInterval: cleanupInterval,
		stopCh:          make(chan struct{}),
		stopped:         false,
	}
	go store.cleanup()
	return store
}

// Get retrieves a session by ID.
// Returns ErrSessionNotFound if the session doesn't exist or has expired.
func (m *MemoryStore) Get(sessionID string) (Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.sessions[sessionID]
	if !exists {
		defaultLogger.Debug("session not found",
			"session_id", sessionID)
		return nil, ErrSessionNotFound
	}

	// Check if session has expired
	if time.Now().After(entry.expiresAt) {
		defaultLogger.Info("session expired",
			"session_id", sessionID,
			"expired_at", entry.expiresAt)
		return nil, ErrSessionNotFound
	}

	defaultLogger.Debug("session retrieved",
		"session_id", sessionID)

	return entry.session, nil
}

// Set stores a session with the given ID.
// The session will expire after the configured TTL (default: 30 days).
func (m *MemoryStore) Set(sessionID string, session Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	expiresAt := time.Now().Add(m.ttl)
	m.sessions[sessionID] = &sessionEntry{
		session:   session,
		expiresAt: expiresAt,
	}

	defaultLogger.Info("session created",
		"session_id", sessionID,
		"expires_at", expiresAt,
		"ttl", m.ttl)

	return nil
}

// Delete removes a session by ID.
func (m *MemoryStore) Delete(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if session exists for logging purposes
	if _, exists := m.sessions[sessionID]; exists {
		defaultLogger.Info("session deleted",
			"session_id", sessionID)
	}

	delete(m.sessions, sessionID)
	return nil
}

// Stop gracefully stops the cleanup goroutine.
// Call this when shutting down the application to avoid goroutine leaks.
func (m *MemoryStore) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.stopped {
		close(m.stopCh)
		m.stopped = true
	}
}

// cleanup runs periodically to remove expired sessions.
func (m *MemoryStore) cleanup() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.removeExpiredSessions()
		case <-m.stopCh:
			return
		}
	}
}

// removeExpiredSessions removes all expired sessions from the store.
func (m *MemoryStore) removeExpiredSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	expiredCount := 0
	for sessionID, entry := range m.sessions {
		if now.After(entry.expiresAt) {
			delete(m.sessions, sessionID)
			expiredCount++
		}
	}

	if expiredCount > 0 {
		defaultLogger.Info("expired sessions cleaned up",
			"count", expiredCount,
			"remaining_sessions", len(m.sessions))
	}
}

// GenerateSessionID creates a cryptographically secure random session ID.
func GenerateSessionID() string {
	return generateSecureRandomString(32)
}

// generateSecureRandomString generates a cryptographically secure random string.
func generateSecureRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:length]
}
