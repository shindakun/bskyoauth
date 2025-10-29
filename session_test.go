package bskyoauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync"
	"testing"
	"time"
)

// TestGenerateSessionID verifies that session IDs are generated correctly.
func TestGenerateSessionID(t *testing.T) {
	id := GenerateSessionID()

	if len(id) != 32 {
		t.Errorf("Expected session ID length of 32, got %d", len(id))
	}

	// Session ID should only contain base64 URL-safe characters
	for _, c := range id {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			t.Errorf("Session ID contains invalid character: %c", c)
		}
	}
}

// TestGenerateSessionIDUniqueness verifies that generated session IDs are unique.
func TestGenerateSessionIDUniqueness(t *testing.T) {
	ids := make(map[string]bool)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		id := GenerateSessionID()
		if ids[id] {
			t.Errorf("Generated duplicate session ID: %s", id)
		}
		ids[id] = true
	}

	if len(ids) != iterations {
		t.Errorf("Expected %d unique IDs, got %d", iterations, len(ids))
	}
}

// TestNewMemorySessionStore verifies proper initialization of MemorySessionStore.
func TestNewMemorySessionStore(t *testing.T) {
	store := NewMemorySessionStore()

	if store == nil {
		t.Fatal("NewMemorySessionStore returned nil")
	}

	// Test that we can use the store
	_, err := store.Get("nonexistent")
	if err != ErrSessionNotFound {
		t.Error("Expected ErrSessionNotFound for nonexistent session")
	}
}

// TestMemorySessionStoreSetAndGet verifies basic Set and Get operations.
func TestMemorySessionStoreSetAndGet(t *testing.T) {
	store := NewMemorySessionStore()
	sessionID := "test-session-123"

	// Create a test session
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	session := &Session{
		DID:          "did:plc:test123",
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		DPoPKey:      key,
		PDS:          "https://test.pds.com",
		DPoPNonce:    "test-nonce",
	}

	// Set the session
	err := store.Set(sessionID, session)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Get the session
	retrieved, err := store.Get(sessionID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Retrieved session is nil")
	}

	// Verify all fields
	if retrieved.DID != session.DID {
		t.Errorf("DID mismatch: expected %s, got %s", session.DID, retrieved.DID)
	}

	if retrieved.AccessToken != session.AccessToken {
		t.Errorf("AccessToken mismatch: expected %s, got %s", session.AccessToken, retrieved.AccessToken)
	}

	if retrieved.RefreshToken != session.RefreshToken {
		t.Errorf("RefreshToken mismatch: expected %s, got %s", session.RefreshToken, retrieved.RefreshToken)
	}

	if retrieved.PDS != session.PDS {
		t.Errorf("PDS mismatch: expected %s, got %s", session.PDS, retrieved.PDS)
	}

	if retrieved.DPoPNonce != session.DPoPNonce {
		t.Errorf("DPoPNonce mismatch: expected %s, got %s", session.DPoPNonce, retrieved.DPoPNonce)
	}

	if retrieved.DPoPKey != session.DPoPKey {
		t.Error("DPoPKey mismatch")
	}
}

// TestMemorySessionStoreGetNotFound verifies error handling for non-existent sessions.
func TestMemorySessionStoreGetNotFound(t *testing.T) {
	store := NewMemorySessionStore()

	_, err := store.Get("non-existent-session")
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound, got %v", err)
	}
}

// TestMemorySessionStoreDelete verifies session deletion.
func TestMemorySessionStoreDelete(t *testing.T) {
	store := NewMemorySessionStore()
	sessionID := "test-session-delete"

	// Create and set a session
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	session := &Session{
		DID:         "did:plc:test123",
		AccessToken: "test-token",
		DPoPKey:     key,
	}

	err := store.Set(sessionID, session)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Verify it exists
	_, err = store.Get(sessionID)
	if err != nil {
		t.Fatalf("Get failed before delete: %v", err)
	}

	// Delete the session
	err = store.Delete(sessionID)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify it no longer exists
	_, err = store.Get(sessionID)
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound after delete, got %v", err)
	}
}

// TestMemorySessionStoreDeleteNonExistent verifies deleting non-existent session doesn't error.
func TestMemorySessionStoreDeleteNonExistent(t *testing.T) {
	store := NewMemorySessionStore()

	// Delete should not return an error even if session doesn't exist
	err := store.Delete("non-existent-session")
	if err != nil {
		t.Errorf("Delete of non-existent session returned error: %v", err)
	}
}

// TestMemorySessionStoreUpdate verifies that sessions can be updated.
func TestMemorySessionStoreUpdate(t *testing.T) {
	store := NewMemorySessionStore()
	sessionID := "test-session-update"

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create initial session
	session1 := &Session{
		DID:         "did:plc:test123",
		AccessToken: "token-v1",
		DPoPKey:     key,
		DPoPNonce:   "nonce-v1",
	}

	err := store.Set(sessionID, session1)
	if err != nil {
		t.Fatalf("Initial Set failed: %v", err)
	}

	// Update with new session data
	session2 := &Session{
		DID:         "did:plc:test123",
		AccessToken: "token-v2",
		DPoPKey:     key,
		DPoPNonce:   "nonce-v2",
	}

	err = store.Set(sessionID, session2)
	if err != nil {
		t.Fatalf("Update Set failed: %v", err)
	}

	// Verify updated values
	retrieved, err := store.Get(sessionID)
	if err != nil {
		t.Fatalf("Get after update failed: %v", err)
	}

	if retrieved.AccessToken != "token-v2" {
		t.Errorf("Expected updated AccessToken 'token-v2', got %s", retrieved.AccessToken)
	}

	if retrieved.DPoPNonce != "nonce-v2" {
		t.Errorf("Expected updated DPoPNonce 'nonce-v2', got %s", retrieved.DPoPNonce)
	}
}

// TestMemorySessionStoreMultipleSessions verifies storing multiple sessions.
func TestMemorySessionStoreMultipleSessions(t *testing.T) {
	store := NewMemorySessionStore()

	// Create and store multiple sessions
	sessionCount := 10
	sessionIDs := make([]string, sessionCount)
	for i := 0; i < sessionCount; i++ {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sessionID := GenerateSessionID()
		sessionIDs[i] = sessionID
		session := &Session{
			DID:         "did:plc:test" + string(rune(i)),
			AccessToken: "token-" + string(rune(i)),
			DPoPKey:     key,
		}

		err := store.Set(sessionID, session)
		if err != nil {
			t.Fatalf("Set failed for session %d: %v", i, err)
		}
	}

	// Verify all sessions can be retrieved
	for i, sid := range sessionIDs {
		_, err := store.Get(sid)
		if err != nil {
			t.Errorf("Failed to get session %d: %v", i, err)
		}
	}
}

// TestMemorySessionStoreConcurrentAccess verifies thread-safe concurrent operations.
func TestMemorySessionStoreConcurrentAccess(t *testing.T) {
	store := NewMemorySessionStore()
	goroutines := 50
	operationsPerGoroutine := 20

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Launch multiple goroutines performing concurrent operations
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()

			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

			for j := 0; j < operationsPerGoroutine; j++ {
				sessionID := GenerateSessionID()

				// Set session
				session := &Session{
					DID:         "did:plc:concurrent" + string(rune(id)) + string(rune(j)),
					AccessToken: "token",
					DPoPKey:     key,
				}
				store.Set(sessionID, session)

				// Get session
				store.Get(sessionID)

				// Update session
				session.DPoPNonce = "updated-nonce"
				store.Set(sessionID, session)

				// Delete session
				store.Delete(sessionID)
			}
		}(i)
	}

	wg.Wait()

	// Test passes if no race conditions occur
	t.Log("Concurrent access test completed successfully")
}

// TestMemorySessionStoreConcurrentReadWrite verifies concurrent reads and writes.
func TestMemorySessionStoreConcurrentReadWrite(t *testing.T) {
	store := NewMemorySessionStore()
	sessionID := "shared-session"

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	session := &Session{
		DID:         "did:plc:shared",
		AccessToken: "token",
		DPoPKey:     key,
		DPoPNonce:   "nonce-0",
	}

	// Set initial session
	store.Set(sessionID, session)

	var wg sync.WaitGroup
	readers := 20
	writers := 10

	// Launch readers
	wg.Add(readers)
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				store.Get(sessionID)
			}
		}()
	}

	// Launch writers
	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				updatedSession := &Session{
					DID:         "did:plc:shared",
					AccessToken: "token",
					DPoPKey:     key,
					DPoPNonce:   "nonce-" + string(rune(id)) + string(rune(j)),
				}
				store.Set(sessionID, updatedSession)
			}
		}(i)
	}

	wg.Wait()

	// Verify session still exists and is valid
	retrieved, err := store.Get(sessionID)
	if err != nil {
		t.Fatalf("Session not found after concurrent access: %v", err)
	}

	if retrieved.DID != "did:plc:shared" {
		t.Errorf("Session corrupted after concurrent access")
	}

	t.Log("Concurrent read/write test completed successfully")
}

// TestSessionStoreInterface verifies that MemorySessionStore implements SessionStore.
func TestSessionStoreInterface(t *testing.T) {
	var _ SessionStore = (*MemorySessionStore)(nil)
	t.Log("MemorySessionStore correctly implements SessionStore interface")
}

// TestSessionFieldPersistence verifies all Session fields are preserved.
func TestSessionFieldPersistence(t *testing.T) {
	store := NewMemorySessionStore()
	sessionID := "test-all-fields"

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create session with all fields populated
	session := &Session{
		DID:          "did:plc:abc123xyz",
		AccessToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		RefreshToken: "refresh_token_value_here",
		DPoPKey:      key,
		PDS:          "https://pds.example.com",
		DPoPNonce:    "server_provided_nonce_123",
	}

	// Store the session
	err := store.Set(sessionID, session)
	if err != nil {
		t.Fatalf("Failed to store session: %v", err)
	}

	// Retrieve and verify all fields
	retrieved, err := store.Get(sessionID)
	if err != nil {
		t.Fatalf("Failed to retrieve session: %v", err)
	}

	if retrieved.DID != session.DID {
		t.Errorf("DID not preserved: expected %s, got %s", session.DID, retrieved.DID)
	}

	if retrieved.AccessToken != session.AccessToken {
		t.Errorf("AccessToken not preserved")
	}

	if retrieved.RefreshToken != session.RefreshToken {
		t.Errorf("RefreshToken not preserved")
	}

	if retrieved.PDS != session.PDS {
		t.Errorf("PDS not preserved: expected %s, got %s", session.PDS, retrieved.PDS)
	}

	if retrieved.DPoPNonce != session.DPoPNonce {
		t.Errorf("DPoPNonce not preserved: expected %s, got %s", session.DPoPNonce, retrieved.DPoPNonce)
	}

	if retrieved.DPoPKey == nil {
		t.Error("DPoPKey is nil after retrieval")
	}

	// Verify the DPoP key is the same instance
	if retrieved.DPoPKey != session.DPoPKey {
		t.Error("DPoPKey pointer not preserved")
	}
}

// TestMemorySessionStoreStressTest performs stress testing with many operations.
func TestMemorySessionStoreStressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	store := NewMemorySessionStore()
	operations := 10000

	for i := 0; i < operations; i++ {
		sessionID := GenerateSessionID()
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

		session := &Session{
			DID:         "did:plc:stress" + string(rune(i)),
			AccessToken: "token-" + string(rune(i)),
			DPoPKey:     key,
		}

		// Set
		store.Set(sessionID, session)

		// Get
		retrieved, err := store.Get(sessionID)
		if err != nil {
			t.Fatalf("Get failed at iteration %d: %v", i, err)
		}

		// Verify
		if retrieved.DID != session.DID {
			t.Fatalf("Data corruption at iteration %d", i)
		}

		// Delete every 10th session to keep memory reasonable
		if i%10 == 0 {
			store.Delete(sessionID)
		}
	}

	t.Logf("Stress test completed: %d operations", operations)
}

// TestMemorySessionStoreExpiration verifies sessions expire after TTL.
func TestMemorySessionStoreExpiration(t *testing.T) {
	// Create store with 200ms TTL
	store := NewMemorySessionStoreWithTTL(200*time.Millisecond, 1*time.Minute)
	defer store.Stop()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sessionID := "test-expiration"
	session := &Session{
		DID:         "did:plc:expire-test",
		AccessToken: "token",
		DPoPKey:     key,
	}

	// Store session
	err := store.Set(sessionID, session)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Should be retrievable immediately
	retrieved, err := store.Get(sessionID)
	if err != nil {
		t.Fatalf("Get before expiration failed: %v", err)
	}
	if retrieved.DID != session.DID {
		t.Error("Retrieved session doesn't match")
	}

	// Wait for expiration
	time.Sleep(250 * time.Millisecond)

	// Should now return ErrSessionNotFound
	_, err = store.Get(sessionID)
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound after expiration, got %v", err)
	}
}

// TestMemorySessionStoreCleanup verifies automatic cleanup of expired sessions.
func TestMemorySessionStoreCleanup(t *testing.T) {
	// Create store with 100ms TTL and 50ms cleanup interval
	store := NewMemorySessionStoreWithTTL(100*time.Millisecond, 50*time.Millisecond)
	defer store.Stop()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Store 5 sessions and keep their IDs
	sessionIDs := make([]string, 5)
	for i := 0; i < 5; i++ {
		sessionID := GenerateSessionID()
		sessionIDs[i] = sessionID
		session := &Session{
			DID:         "did:plc:cleanup" + string(rune(i)),
			AccessToken: "token",
			DPoPKey:     key,
		}
		store.Set(sessionID, session)
	}

	// Verify all sessions initially exist
	for _, sid := range sessionIDs {
		_, err := store.Get(sid)
		if err != nil {
			t.Errorf("Session should exist initially: %v", err)
		}
	}

	// Wait for expiration and cleanup (100ms + 50ms + buffer)
	time.Sleep(200 * time.Millisecond)

	// Verify sessions were cleaned up by trying to retrieve them
	for _, sid := range sessionIDs {
		_, err := store.Get(sid)
		if err != ErrSessionNotFound {
			t.Error("Session should have been cleaned up")
		}
	}
}

// TestMemorySessionStoreStop verifies Stop() terminates cleanup goroutine.
func TestMemorySessionStoreStop(t *testing.T) {
	store := NewMemorySessionStoreWithTTL(1*time.Hour, 100*time.Millisecond)

	// Stop the store
	store.Stop()

	// Calling Stop again should be safe (shouldn't panic)
	store.Stop()

	// Store should still function after Stop
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	session := &Session{
		DID:         "did:plc:test-after-stop",
		AccessToken: "token",
		DPoPKey:     key,
	}
	err := store.Set("test-id", session)
	if err != nil {
		t.Errorf("Set should work after Stop: %v", err)
	}
}

// TestMemorySessionStoreCustomTTL verifies custom TTL is respected.
func TestMemorySessionStoreCustomTTL(t *testing.T) {
	customTTL := 500 * time.Millisecond
	store := NewMemorySessionStoreWithTTL(customTTL, 1*time.Minute)
	defer store.Stop()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sessionID := "test-custom-ttl"
	session := &Session{
		DID:         "did:plc:custom-ttl",
		AccessToken: "token",
		DPoPKey:     key,
	}

	store.Set(sessionID, session)

	// Should be valid before TTL
	time.Sleep(300 * time.Millisecond)
	_, err := store.Get(sessionID)
	if err != nil {
		t.Errorf("Session should still be valid at 300ms: %v", err)
	}

	// Should be expired after TTL
	time.Sleep(300 * time.Millisecond) // Total: 600ms > 500ms TTL
	_, err = store.Get(sessionID)
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound after TTL, got %v", err)
	}
}

// TestMemorySessionStoreDefaultTTL verifies default store creation works.
func TestMemorySessionStoreDefaultTTL(t *testing.T) {
	store := NewMemorySessionStore()
	defer store.Stop()

	// Test that default store works correctly
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sessionID := "test-default"
	session := &Session{
		DID:         "did:plc:default-test",
		AccessToken: "token",
		DPoPKey:     key,
	}

	err := store.Set(sessionID, session)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	_, err = store.Get(sessionID)
	if err != nil {
		t.Errorf("Get failed: %v", err)
	}
}

// TestMemorySessionStoreConcurrentExpiration verifies thread-safe cleanup.
func TestMemorySessionStoreConcurrentExpiration(t *testing.T) {
	store := NewMemorySessionStoreWithTTL(100*time.Millisecond, 50*time.Millisecond)
	defer store.Stop()

	var wg sync.WaitGroup
	goroutines := 10

	// Concurrent writes
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			for j := 0; j < 10; j++ {
				sessionID := GenerateSessionID()
				session := &Session{
					DID:         "did:plc:concurrent" + string(rune(id)) + string(rune(j)),
					AccessToken: "token",
					DPoPKey:     key,
				}
				store.Set(sessionID, session)
				time.Sleep(5 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()

	// Wait for cleanup to process
	time.Sleep(200 * time.Millisecond)

	t.Log("Concurrent expiration test completed successfully")
}

// TestMemorySessionStoreExpirationOnGet verifies expired sessions return error on Get.
func TestMemorySessionStoreExpirationOnGet(t *testing.T) {
	store := NewMemorySessionStoreWithTTL(100*time.Millisecond, 10*time.Minute)
	defer store.Stop()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sessionID := "test-get-expiration"
	session := &Session{
		DID:         "did:plc:get-expire",
		AccessToken: "token",
		DPoPKey:     key,
	}

	store.Set(sessionID, session)

	// Wait for expiration (but before cleanup runs)
	time.Sleep(150 * time.Millisecond)

	// Get should detect expiration even if cleanup hasn't run yet
	_, err := store.Get(sessionID)
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound on Get of expired session, got %v", err)
	}
}
