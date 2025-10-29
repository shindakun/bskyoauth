package bskyoauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/shindakun/bskyoauth/internal/oauth"
)

func TestOAuthStateStoreExpiration(t *testing.T) {
	// Create a store with short TTL for testing
	store := oauth.NewStateStore(100 * time.Millisecond)
	defer store.Stop()

	// Generate test key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store a state
	testState := &oauth.State{
		CodeVerifier:   "test-verifier",
		DPoPKey:        key,
		ExpectedIssuer: "https://bsky.social",
	}
	store.Set("test-state", testState)

	// Should be retrievable immediately
	retrieved, exists := store.Get("test-state")
	if !exists {
		t.Fatal("State should exist immediately after setting")
	}
	if retrieved.CodeVerifier != "test-verifier" {
		t.Errorf("Expected verifier 'test-verifier', got '%s'", retrieved.CodeVerifier)
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should be expired now
	_, exists = store.Get("test-state")
	if exists {
		t.Error("State should be expired after TTL")
	}
}

func TestOAuthStateStoreCleanup(t *testing.T) {
	// Create a store with short TTL and short cleanup interval for testing
	store := oauth.NewStateStoreWithInterval(50*time.Millisecond, 100*time.Millisecond)
	defer store.Stop()

	// Generate test key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store multiple states
	for i := 0; i < 10; i++ {
		testState := &oauth.State{
			CodeVerifier:   "test-verifier",
			DPoPKey:        key,
			ExpectedIssuer: "https://bsky.social",
		}
		store.Set(string(rune(i)), testState)
	}

	// Verify all states exist by trying to retrieve them
	for i := 0; i < 10; i++ {
		if _, exists := store.Get(string(rune(i))); !exists {
			t.Errorf("State %d should exist", i)
		}
	}

	// Wait for expiration and at least one cleanup cycle
	time.Sleep(200 * time.Millisecond)

	// Verify states have been cleaned up
	for i := 0; i < 10; i++ {
		if _, exists := store.Get(string(rune(i))); exists {
			t.Errorf("State %d should be cleaned up", i)
		}
	}
}

func TestOAuthStateStoreDelete(t *testing.T) {
	store := oauth.NewStateStore(1 * time.Minute)
	defer store.Stop()

	// Generate test key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store a state
	testState := &oauth.State{
		CodeVerifier:   "test-verifier",
		DPoPKey:        key,
		ExpectedIssuer: "https://bsky.social",
	}
	store.Set("test-state", testState)

	// Verify it exists
	_, exists := store.Get("test-state")
	if !exists {
		t.Fatal("State should exist after setting")
	}

	// Delete it
	store.Delete("test-state")

	// Verify it's gone
	_, exists = store.Get("test-state")
	if exists {
		t.Error("State should not exist after deletion")
	}
}

func TestOAuthStateStoreStop(t *testing.T) {
	store := oauth.NewStateStore(1 * time.Minute)

	// Stop the store - should be safe to call
	store.Stop()

	// Calling stop again should also be safe (no panic)
	store.Stop()

	// Test passes if no panic occurs
}

func TestIssuerValidation(t *testing.T) {
	store := oauth.NewStateStore(1 * time.Minute)
	defer store.Stop()

	// Generate test key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store a state with expected issuer
	testState := &oauth.State{
		CodeVerifier:   "test-verifier",
		DPoPKey:        key,
		ExpectedIssuer: "https://bsky.social",
	}
	store.Set("test-state", testState)

	// Retrieve and verify expected issuer is stored
	retrieved, exists := store.Get("test-state")
	if !exists {
		t.Fatal("State should exist")
	}
	if retrieved.ExpectedIssuer != "https://bsky.social" {
		t.Errorf("Expected issuer 'https://bsky.social', got '%s'", retrieved.ExpectedIssuer)
	}
}
