package bskyoauth

import (
	"time"

	"github.com/shindakun/bskyoauth/internal/session"
)

// Re-export session-related errors for backward compatibility
var (
	// ErrSessionNotFound is returned when a session ID doesn't exist
	ErrSessionNotFound = session.ErrSessionNotFound

	// ErrInvalidSession is returned when a session is invalid or expired
	ErrInvalidSession = session.ErrInvalidSession
)

// MemorySessionStore is an in-memory implementation of SessionStore with automatic expiration.
// This is a wrapper around internal/session.MemoryStore to maintain backward compatibility.
type MemorySessionStore struct {
	store *session.MemoryStore
}

// NewMemorySessionStore creates a new in-memory session store with default TTL (30 days).
// Sessions automatically expire and are cleaned up every 5 minutes.
func NewMemorySessionStore() *MemorySessionStore {
	// Set the logger for the internal session package
	session.SetLogger(Logger)
	return &MemorySessionStore{
		store: session.NewMemoryStore(),
	}
}

// NewMemorySessionStoreWithTTL creates a new in-memory session store with custom TTL and cleanup interval.
// ttl: how long sessions remain valid before expiring
// cleanupInterval: how often the cleanup goroutine runs to remove expired sessions
func NewMemorySessionStoreWithTTL(ttl, cleanupInterval time.Duration) *MemorySessionStore {
	// Set the logger for the internal session package
	session.SetLogger(Logger)
	return &MemorySessionStore{
		store: session.NewMemoryStoreWithTTL(ttl, cleanupInterval),
	}
}

// Get retrieves a session by ID.
// Returns ErrSessionNotFound if the session doesn't exist or has expired.
func (m *MemorySessionStore) Get(sessionID string) (*Session, error) {
	sess, err := m.store.Get(sessionID)
	if err != nil {
		return nil, err
	}
	return sess.(*Session), nil
}

// Set stores a session with the given ID.
// The session will expire after the configured TTL (default: 30 days).
func (m *MemorySessionStore) Set(sessionID string, session *Session) error {
	return m.store.Set(sessionID, session)
}

// Delete removes a session by ID.
func (m *MemorySessionStore) Delete(sessionID string) error {
	return m.store.Delete(sessionID)
}

// Stop gracefully stops the cleanup goroutine.
// Call this when shutting down the application to avoid goroutine leaks.
func (m *MemorySessionStore) Stop() {
	m.store.Stop()
}

// GenerateSessionID creates a cryptographically secure random session ID.
func GenerateSessionID() string {
	return session.GenerateSessionID()
}
