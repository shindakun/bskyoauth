package bskyoauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

func TestOAuthStateStoreExpiration(t *testing.T) {
	// Create a store with short TTL for testing
	store := newOAuthStateStore(100 * time.Millisecond)
	defer store.stop()

	// Generate test key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store a state
	testState := &internalOAuthState{
		CodeVerifier:   "test-verifier",
		DPoPKey:        key,
		ExpectedIssuer: "https://bsky.social",
	}
	store.set("test-state", testState)

	// Should be retrievable immediately
	retrieved, exists := store.get("test-state")
	if !exists {
		t.Fatal("State should exist immediately after setting")
	}
	if retrieved.CodeVerifier != "test-verifier" {
		t.Errorf("Expected verifier 'test-verifier', got '%s'", retrieved.CodeVerifier)
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should be expired now
	_, exists = store.get("test-state")
	if exists {
		t.Error("State should be expired after TTL")
	}
}

func TestOAuthStateStoreCleanup(t *testing.T) {
	// Create a store with short TTL and short cleanup interval for testing
	store := newOAuthStateStoreWithInterval(50*time.Millisecond, 100*time.Millisecond)
	defer store.stop()

	// Generate test key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store multiple states
	for i := 0; i < 10; i++ {
		testState := &internalOAuthState{
			CodeVerifier:   "test-verifier",
			DPoPKey:        key,
			ExpectedIssuer: "https://bsky.social",
		}
		store.set(string(rune(i)), testState)
	}

	// Verify all states exist
	store.mu.RLock()
	initialCount := len(store.states)
	store.mu.RUnlock()

	if initialCount != 10 {
		t.Errorf("Expected 10 states, got %d", initialCount)
	}

	// Wait for expiration and at least one cleanup cycle
	time.Sleep(200 * time.Millisecond)

	// Verify states have been cleaned up
	store.mu.RLock()
	finalCount := len(store.states)
	store.mu.RUnlock()

	if finalCount != 0 {
		t.Errorf("Expected 0 states after cleanup, got %d", finalCount)
	}
}

func TestOAuthStateStoreDelete(t *testing.T) {
	store := newOAuthStateStore(1 * time.Minute)
	defer store.stop()

	// Generate test key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store a state
	testState := &internalOAuthState{
		CodeVerifier:   "test-verifier",
		DPoPKey:        key,
		ExpectedIssuer: "https://bsky.social",
	}
	store.set("test-state", testState)

	// Verify it exists
	_, exists := store.get("test-state")
	if !exists {
		t.Fatal("State should exist after setting")
	}

	// Delete it
	store.delete("test-state")

	// Verify it's gone
	_, exists = store.get("test-state")
	if exists {
		t.Error("State should not exist after deletion")
	}
}

func TestOAuthStateStoreStop(t *testing.T) {
	store := newOAuthStateStore(1 * time.Minute)

	// Stop the store
	store.stop()

	// Verify stopped flag is set
	if !store.stopped {
		t.Error("Store should be marked as stopped")
	}

	// Calling stop again should be safe
	store.stop()

	// Should still be marked as stopped
	if !store.stopped {
		t.Error("Store should still be marked as stopped after second call")
	}
}

func TestIssuerValidation(t *testing.T) {
	store := newOAuthStateStore(1 * time.Minute)
	defer store.stop()

	// Generate test key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store a state with expected issuer
	testState := &internalOAuthState{
		CodeVerifier:   "test-verifier",
		DPoPKey:        key,
		ExpectedIssuer: "https://bsky.social",
	}
	store.set("test-state", testState)

	// Retrieve and verify expected issuer is stored
	retrieved, exists := store.get("test-state")
	if !exists {
		t.Fatal("State should exist")
	}
	if retrieved.ExpectedIssuer != "https://bsky.social" {
		t.Errorf("Expected issuer 'https://bsky.social', got '%s'", retrieved.ExpectedIssuer)
	}
}
