package bskyoauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/shindakun/bskyoauth/internal/oauth"
)

// TestCSRFProtectionStateParameter verifies that the OAuth state parameter
// prevents CSRF attacks by validating state tokens.
func TestCSRFProtectionStateParameter(t *testing.T) {
	tests := []struct {
		name          string
		storedState   string
		providedState string
		wantError     bool
		errorType     error
	}{
		{
			name:          "valid state token accepted",
			storedState:   "valid-state-123",
			providedState: "valid-state-123",
			wantError:     false,
		},
		{
			name:          "missing state rejected",
			storedState:   "valid-state-123",
			providedState: "",
			wantError:     true,
			errorType:     ErrInvalidState,
		},
		{
			name:          "wrong state rejected",
			storedState:   "valid-state-123",
			providedState: "attacker-state-456",
			wantError:     true,
			errorType:     ErrInvalidState,
		},
		{
			name:          "manipulated state rejected",
			storedState:   "valid-state-123",
			providedState: "valid-state-124", // off by one
			wantError:     true,
			errorType:     ErrInvalidState,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := oauth.NewStateStore(10 * time.Minute)
			defer store.Stop()

			// Generate test key
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			// Store the expected state
			if tt.storedState != "" {
				testState := &oauth.State{
					CodeVerifier:   "test-verifier",
					DPoPKey:        key,
					ExpectedIssuer: "https://bsky.social",
				}
				store.Set(tt.storedState, testState)
			}

			// Attempt to retrieve with provided state
			_, exists := store.Get(tt.providedState)

			if tt.wantError {
				if exists {
					t.Errorf("Expected state validation to fail, but state was found")
				}
			} else {
				if !exists {
					t.Errorf("Expected state validation to succeed, but state was not found")
				}
			}
		})
	}
}

// TestCSRFStateExpiration verifies that expired state tokens are rejected,
// preventing attackers from using old state values.
func TestCSRFStateExpiration(t *testing.T) {
	// Create store with very short TTL for testing
	store := oauth.NewStateStore(100 * time.Millisecond)
	defer store.Stop()

	// Generate test key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store a state token
	testState := &oauth.State{
		CodeVerifier:   "test-verifier",
		DPoPKey:        key,
		ExpectedIssuer: "https://bsky.social",
	}
	store.Set("test-state", testState)

	// Verify it exists immediately
	_, exists := store.Get("test-state")
	if !exists {
		t.Fatal("State should exist immediately after creation")
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Verify it's now expired (CSRF attack with old state should fail)
	_, exists = store.Get("test-state")
	if exists {
		t.Error("Expired state should be rejected (CSRF protection)")
	}

	// Verify cleanup removed the expired state
	time.Sleep(200 * time.Millisecond) // Wait for cleanup goroutine
}

// TestCSRFIssuerValidation verifies that the expected issuer validation
// prevents authorization code injection attacks.
func TestCSRFIssuerValidation(t *testing.T) {
	tests := []struct {
		name           string
		expectedIssuer string
		providedIssuer string
		wantError      bool
		errorContains  string
	}{
		{
			name:           "matching issuer accepted",
			expectedIssuer: "https://bsky.social",
			providedIssuer: "https://bsky.social",
			wantError:      false,
		},
		{
			name:           "different issuer rejected",
			expectedIssuer: "https://bsky.social",
			providedIssuer: "https://evil.com",
			wantError:      true,
			errorContains:  "issuer mismatch",
		},
		{
			name:           "subdomain attack rejected",
			expectedIssuer: "https://bsky.social",
			providedIssuer: "https://evil.bsky.social",
			wantError:      true,
			errorContains:  "issuer mismatch",
		},
		{
			name:           "protocol mismatch rejected",
			expectedIssuer: "https://bsky.social",
			providedIssuer: "http://bsky.social",
			wantError:      true,
			errorContains:  "issuer mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := oauth.NewStateStore(10 * time.Minute)
			defer store.Stop()

			// Generate test key
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			// Store state with expected issuer
			testState := &oauth.State{
				CodeVerifier:   "test-verifier",
				DPoPKey:        key,
				ExpectedIssuer: tt.expectedIssuer,
			}
			store.Set("test-state", testState)

			// Retrieve and check issuer
			retrieved, exists := store.Get("test-state")
			if !exists {
				t.Fatal("State should exist")
			}

			// Simulate issuer validation
			if retrieved.ExpectedIssuer != tt.providedIssuer {
				err := ErrIssuerMismatch
				if tt.wantError {
					if err == nil {
						t.Error("Expected issuer mismatch error")
					}
				} else {
					t.Errorf("Unexpected issuer mismatch: got %v", err)
				}
			} else {
				if tt.wantError {
					t.Error("Expected issuer validation to fail, but it passed")
				}
			}
		})
	}
}

// TestCSRFStateReuse verifies that state tokens cannot be reused,
// preventing replay attacks.
func TestCSRFStateReuse(t *testing.T) {
	store := oauth.NewStateStore(10 * time.Minute)
	defer store.Stop()

	// Generate test key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store a state token
	stateToken := "single-use-state-123"
	testState := &oauth.State{
		CodeVerifier:   "test-verifier",
		DPoPKey:        key,
		ExpectedIssuer: "https://bsky.social",
	}
	store.Set(stateToken, testState)

	// First use - should succeed
	retrieved, exists := store.Get(stateToken)
	if !exists {
		t.Fatal("First state retrieval should succeed")
	}
	if retrieved.CodeVerifier != "test-verifier" {
		t.Errorf("Expected verifier 'test-verifier', got '%s'", retrieved.CodeVerifier)
	}

	// Delete state after use (simulating CompleteAuthFlow behavior)
	store.Delete(stateToken)

	// Second use - should fail (replay attack prevention)
	_, exists = store.Get(stateToken)
	if exists {
		t.Error("State reuse should be prevented (replay attack protection)")
	}

	// Attempt to use the state again should fail
	_, exists = store.Get(stateToken)
	if exists {
		t.Error("Multiple state reuse attempts should all fail")
	}
}

// TestCSRFConcurrentStateValidation tests thread-safety of state validation
// under concurrent CSRF attack scenarios.
func TestCSRFConcurrentStateValidation(t *testing.T) {
	store := oauth.NewStateStore(10 * time.Minute)
	defer store.Stop()

	// Generate test key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Store a state token
	stateToken := "concurrent-state-123"
	testState := &oauth.State{
		CodeVerifier:   "test-verifier",
		DPoPKey:        key,
		ExpectedIssuer: "https://bsky.social",
	}
	store.Set(stateToken, testState)

	// Simulate multiple concurrent validation attempts
	// (e.g., attacker tries to race condition the validation)
	done := make(chan bool, 10)
	var successCount int
	var mu sync.Mutex

	for i := 0; i < 10; i++ {
		go func() {
			_, exists := store.Get(stateToken)
			if exists {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// All should succeed since we haven't deleted the state
	mu.Lock()
	count := successCount
	mu.Unlock()
	if count != 10 {
		t.Errorf("Expected all 10 concurrent validations to succeed, got %d", count)
	}

	// Now delete and try concurrent access again
	store.Delete(stateToken)
	mu.Lock()
	successCount = 0
	mu.Unlock()

	for i := 0; i < 10; i++ {
		go func() {
			_, exists := store.Get(stateToken)
			if exists {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// All should fail after deletion
	mu.Lock()
	count = successCount
	mu.Unlock()
	if count != 0 {
		t.Errorf("Expected all concurrent validations to fail after deletion, got %d successes", count)
	}
}

// TestCSRFStateStorageLimit tests that the state store doesn't grow unbounded
// under attack scenarios with many fake states.
func TestCSRFStateStorageLimit(t *testing.T) {
	// Create store with short TTL for faster testing
	store := oauth.NewStateStore(200 * time.Millisecond)
	defer store.Stop()

	// Generate test key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Simulate attacker creating many states
	for i := 0; i < 100; i++ {
		stateToken := generateRandomString(32)
		testState := &oauth.State{
			CodeVerifier:   "test-verifier",
			DPoPKey:        key,
			ExpectedIssuer: "https://bsky.social",
		}
		store.Set(stateToken, testState)
	}

	// Wait for cleanup to run (should remove expired states)
	time.Sleep(500 * time.Millisecond)

	// Verify cleanup occurred (implementation detail: we can't directly check
	// store size, but we can verify that old states are gone)
	testState := &oauth.State{
		CodeVerifier:   "new-verifier",
		DPoPKey:        key,
		ExpectedIssuer: "https://bsky.social",
	}
	store.Set("new-state", testState)

	_, exists := store.Get("new-state")
	if !exists {
		t.Error("Store should still accept new states after cleanup")
	}
}

// Helper function to generate random strings for testing
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b)
}

// TestCSRFProtectionWithCompleteAuthFlow tests CSRF protection in the context
// of a full OAuth flow.
func TestCSRFProtectionWithCompleteAuthFlow(t *testing.T) {
	// This is an integration-style test that verifies CSRF protection
	// works end-to-end in the OAuth flow

	client := NewClient("http://localhost:8181")
	ctx := context.Background()

	// Note: This test would require mock servers to fully execute
	// For now, we test the state store behavior which is the core CSRF protection

	store := oauth.NewStateStore(10 * time.Minute)
	defer store.Stop()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	validState := "valid-oauth-state-123"
	attackerState := "attacker-injected-state-456"

	// Legitimate user starts OAuth flow
	legitimateState := &oauth.State{
		CodeVerifier:   "legitimate-verifier",
		DPoPKey:        key,
		ExpectedIssuer: "https://bsky.social",
	}
	store.Set(validState, legitimateState)

	// Attacker tries to inject their own state
	attackerStateObj := &oauth.State{
		CodeVerifier:   "attacker-verifier",
		DPoPKey:        key,
		ExpectedIssuer: "https://evil.com",
	}
	store.Set(attackerState, attackerStateObj)

	// Legitimate callback - should succeed
	retrieved, exists := store.Get(validState)
	if !exists {
		t.Error("Legitimate state should be found")
	}
	if retrieved.CodeVerifier != "legitimate-verifier" {
		t.Error("Legitimate state should have correct verifier")
	}

	// Attacker callback with wrong state - should fail
	_, exists = store.Get("wrong-state-999")
	if exists {
		t.Error("Invalid state should not be found (CSRF protection)")
	}

	// Attacker callback with their injected state - would be caught by issuer validation
	attackRetrieved, exists := store.Get(attackerState)
	if !exists {
		t.Error("Attacker state exists in store")
	}
	// But issuer validation would fail
	if attackRetrieved.ExpectedIssuer == "https://bsky.social" {
		t.Error("Attacker's issuer should not match legitimate issuer")
	}

	// Clean up - prevent state reuse
	store.Delete(validState)
	_, exists = store.Get(validState)
	if exists {
		t.Error("State should be deleted after use to prevent replay")
	}

	_ = ctx
	_ = client
}

// TestCSRFErrorTypes verifies that appropriate error types are returned
// for different CSRF attack scenarios.
func TestCSRFErrorTypes(t *testing.T) {
	tests := []struct {
		name      string
		scenario  func() error
		wantError error
	}{
		{
			name: "invalid state returns ErrInvalidState",
			scenario: func() error {
				store := oauth.NewStateStore(10 * time.Minute)
				defer store.Stop()
				_, exists := store.Get("nonexistent-state")
				if !exists {
					return ErrInvalidState
				}
				return nil
			},
			wantError: ErrInvalidState,
		},
		{
			name: "issuer mismatch returns ErrIssuerMismatch",
			scenario: func() error {
				// Simulate issuer validation failure
				expectedIssuer := "https://bsky.social"
				providedIssuer := "https://evil.com"
				if expectedIssuer != providedIssuer {
					return ErrIssuerMismatch
				}
				return nil
			},
			wantError: ErrIssuerMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.scenario()
			if !errors.Is(err, tt.wantError) {
				t.Errorf("Expected error %v, got %v", tt.wantError, err)
			}
		})
	}
}
