package oauth

import (
	"sync"
	"time"
)

// StateStore manages OAuth state parameters during the authorization flow.
// It provides automatic expiration and cleanup of stale state entries.
type StateStore struct {
	states          map[string]*stateEntry
	mu              sync.RWMutex
	ttl             time.Duration
	cleanupInterval time.Duration
	stopCh          chan struct{}
	stopped         bool
}

// stateEntry represents a stored OAuth state with expiration time.
type stateEntry struct {
	state     *State
	expiresAt time.Time
}

// State holds the OAuth state parameters for an in-flight authorization request.
type State struct {
	CodeVerifier   string
	DPoPKey        interface{} // *ecdsa.PrivateKey
	ExpectedIssuer string      // Expected authorization server for validation
	DID            string      // User's DID for session creation
}

const (
	// DefaultTTL is the default time-to-live for OAuth state entries (10 minutes)
	DefaultTTL = 10 * time.Minute
	// DefaultCleanupInterval is how often the cleanup goroutine runs (1 minute)
	DefaultCleanupInterval = 1 * time.Minute
)

// NewStateStore creates a new OAuth state store with the given TTL.
func NewStateStore(ttl time.Duration) *StateStore {
	return NewStateStoreWithInterval(ttl, DefaultCleanupInterval)
}

// NewStateStoreWithInterval creates a new OAuth state store with custom TTL and cleanup interval.
func NewStateStoreWithInterval(ttl, cleanupInterval time.Duration) *StateStore {
	store := &StateStore{
		states:          make(map[string]*stateEntry),
		ttl:             ttl,
		cleanupInterval: cleanupInterval,
		stopCh:          make(chan struct{}),
	}
	go store.cleanupExpired()
	return store
}

// Set stores an OAuth state with the given key.
func (s *StateStore) Set(key string, state *State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[key] = &stateEntry{
		state:     state,
		expiresAt: time.Now().Add(s.ttl),
	}
}

// Get retrieves an OAuth state by key.
// Returns nil, false if the state doesn't exist or has expired.
func (s *StateStore) Get(key string) (*State, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.states[key]
	if !exists {
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.state, true
}

// Delete removes an OAuth state by key.
func (s *StateStore) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, key)
}

// cleanupExpired removes expired entries from the store.
// Runs in a background goroutine.
func (s *StateStore) cleanupExpired() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for key, entry := range s.states {
				if now.After(entry.expiresAt) {
					delete(s.states, key)
				}
			}
			s.mu.Unlock()
		case <-s.stopCh:
			return
		}
	}
}

// Stop gracefully stops the cleanup goroutine.
// Used for testing and clean shutdown.
func (s *StateStore) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.stopped {
		close(s.stopCh)
		s.stopped = true
	}
}
