package bskyoauth

import (
	"crypto/ecdsa"
	"sync"
	"time"
)

// Session represents an authenticated user session with Bluesky.
type Session struct {
	// DID is the decentralized identifier for the user
	DID string

	// AccessToken is the OAuth access token
	AccessToken string

	// RefreshToken is used to obtain new access tokens
	RefreshToken string

	// DPoPKey is the private key used for DPoP proof generation
	DPoPKey *ecdsa.PrivateKey

	// PDS is the Personal Data Server endpoint for this user
	PDS string

	// DPoPNonce is the server-provided nonce for DPoP proofs
	DPoPNonce string
}

// AuthFlowState contains the state information for an OAuth flow.
type AuthFlowState struct {
	// State is the OAuth state parameter for CSRF protection
	State string

	// CodeVerifier is the PKCE code verifier
	CodeVerifier string

	// DPoPKey is the private key for this authentication flow
	DPoPKey *ecdsa.PrivateKey

	// AuthURL is the authorization URL to redirect the user to
	AuthURL string

	// DID is the user's decentralized identifier
	DID string
}

// SessionStore is an interface for storing and retrieving sessions.
// Implement this interface to provide custom session storage (e.g., Redis, database).
type SessionStore interface {
	// Get retrieves a session by ID
	Get(sessionID string) (*Session, error)

	// Set stores a session with the given ID
	Set(sessionID string, session *Session) error

	// Delete removes a session by ID
	Delete(sessionID string) error
}

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

// AuthServerMetadata contains OAuth authorization server metadata.
type AuthServerMetadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	Issuer                string `json:"issuer"`
}
