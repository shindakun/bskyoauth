package bskyoauth

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

// sessionEntry wraps a session with expiration tracking.
type sessionEntry struct {
	session   *Session
	expiresAt time.Time
}

// MemorySessionStore is an in-memory implementation of SessionStore with automatic expiration.
type MemorySessionStore struct {
	sessions        map[string]*sessionEntry
	mu              sync.RWMutex
	ttl             time.Duration
	cleanupInterval time.Duration
	stopCh          chan struct{}
	stopped         bool
}

// NewMemorySessionStore creates a new in-memory session store with default TTL (30 days).
// Sessions automatically expire and are cleaned up every 5 minutes.
func NewMemorySessionStore() *MemorySessionStore {
	return NewMemorySessionStoreWithTTL(DefaultSessionTTL, DefaultSessionCleanupInterval)
}

// NewMemorySessionStoreWithTTL creates a new in-memory session store with custom TTL and cleanup interval.
// ttl: how long sessions remain valid before expiring
// cleanupInterval: how often the cleanup goroutine runs to remove expired sessions
func NewMemorySessionStoreWithTTL(ttl, cleanupInterval time.Duration) *MemorySessionStore {
	store := &MemorySessionStore{
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
func (m *MemorySessionStore) Get(sessionID string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.sessions[sessionID]
	if !exists {
		return nil, ErrSessionNotFound
	}

	// Check if session has expired
	if time.Now().After(entry.expiresAt) {
		return nil, ErrSessionNotFound
	}

	return entry.session, nil
}

// Set stores a session with the given ID.
// The session will expire after the configured TTL (default: 30 days).
func (m *MemorySessionStore) Set(sessionID string, session *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions[sessionID] = &sessionEntry{
		session:   session,
		expiresAt: time.Now().Add(m.ttl),
	}
	return nil
}

// Delete removes a session by ID.
func (m *MemorySessionStore) Delete(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, sessionID)
	return nil
}

// Stop gracefully stops the cleanup goroutine.
// Call this when shutting down the application to avoid goroutine leaks.
func (m *MemorySessionStore) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.stopped {
		close(m.stopCh)
		m.stopped = true
	}
}

// cleanup runs periodically to remove expired sessions.
func (m *MemorySessionStore) cleanup() {
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
func (m *MemorySessionStore) removeExpiredSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for sessionID, entry := range m.sessions {
		if now.After(entry.expiresAt) {
			delete(m.sessions, sessionID)
		}
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
