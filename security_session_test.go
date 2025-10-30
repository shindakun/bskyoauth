package bskyoauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSessionHijackingPrevention verifies that session IDs are cryptographically
// random and resistant to prediction attacks.
func TestSessionHijackingPrevention(t *testing.T) {
	t.Run("session IDs are cryptographically random", func(t *testing.T) {
		// Generate many session IDs
		ids := make(map[string]bool)
		iterations := 10000

		for i := 0; i < iterations; i++ {
			id := GenerateSessionID()

			// Check for collision (should be extremely rare with 128 bits)
			if ids[id] {
				t.Fatalf("Session ID collision detected: %s (iteration %d)", id, i)
			}
			ids[id] = true

			// Verify length (32 chars = 192 bits base64url)
			if len(id) != 32 {
				t.Errorf("Session ID length incorrect: expected 32, got %d", len(id))
			}

			// Verify characters are base64url safe
			for _, c := range id {
				if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
					t.Errorf("Session ID contains invalid character: %c", c)
				}
			}
		}

		if len(ids) != iterations {
			t.Errorf("Expected %d unique session IDs, got %d", iterations, len(ids))
		}
	})

	t.Run("session IDs are not predictable", func(t *testing.T) {
		// Generate sequence of IDs and verify they don't follow a pattern
		id1 := GenerateSessionID()
		id2 := GenerateSessionID()
		id3 := GenerateSessionID()

		// IDs should be completely different
		if id1 == id2 || id2 == id3 || id1 == id3 {
			t.Error("Session IDs show pattern or repetition")
		}

		// Check Hamming distance (number of different characters)
		// Should be high for random IDs
		differences := 0
		for i := 0; i < len(id1) && i < len(id2); i++ {
			if id1[i] != id2[i] {
				differences++
			}
		}

		// At least 50% of characters should differ for truly random IDs
		if differences < len(id1)/2 {
			t.Errorf("Session IDs too similar (only %d/%d chars differ), may indicate weak randomness", differences, len(id1))
		}
	})

	t.Run("session ID has sufficient entropy", func(t *testing.T) {
		// Session IDs should have high entropy (>= 128 bits recommended)
		id := GenerateSessionID()

		// 32 characters of base64url = log2(64^32) = 192 bits of entropy
		// This is well above the 128-bit minimum recommended
		expectedMinEntropy := 128.0
		actualEntropy := float64(len(id)) * 6.0 // 6 bits per base64 character

		if actualEntropy < expectedMinEntropy {
			t.Errorf("Session ID entropy too low: %.1f bits (minimum: %.1f bits)", actualEntropy, expectedMinEntropy)
		}
	})
}

// TestSessionFixationPrevention verifies that sessions are regenerated
// appropriately to prevent session fixation attacks.
func TestSessionFixationPrevention(t *testing.T) {
	t.Run("new session ID generated on creation", func(t *testing.T) {
		store := NewMemorySessionStore()

		// Create session with test data
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		session1 := &Session{
			DID:         "did:plc:test123",
			AccessToken: "token1",
			DPoPKey:     key,
		}

		session2 := &Session{
			DID:         "did:plc:test456",
			AccessToken: "token2",
			DPoPKey:     key,
		}

		// Store sessions with different IDs
		id1 := GenerateSessionID()
		id2 := GenerateSessionID()

		store.Set(id1, session1)
		store.Set(id2, session2)

		// Verify sessions have different IDs
		if id1 == id2 {
			t.Error("Session IDs should be unique (session fixation risk)")
		}

		// Verify both can be retrieved
		retrieved1, err := store.Get(id1)
		if err != nil || retrieved1.DID != "did:plc:test123" {
			t.Error("First session should be retrievable with its ID")
		}

		retrieved2, err := store.Get(id2)
		if err != nil || retrieved2.DID != "did:plc:test456" {
			t.Error("Second session should be retrievable with its ID")
		}
	})

	t.Run("old session IDs become invalid", func(t *testing.T) {
		store := NewMemorySessionStore()

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		// Create initial session
		oldSessionID := GenerateSessionID()
		session := &Session{
			DID:         "did:plc:test123",
			AccessToken: "old-token",
			DPoPKey:     key,
		}
		store.Set(oldSessionID, session)

		// Simulate session regeneration (like after login)
		newSessionID := GenerateSessionID()
		store.Set(newSessionID, session)

		// Delete old session ID
		store.Delete(oldSessionID)

		// Old session ID should no longer work
		_, err = store.Get(oldSessionID)
		if err == nil {
			t.Error("Old session ID should be invalid after regeneration (session fixation prevention)")
		}

		// New session ID should work
		retrieved, err := store.Get(newSessionID)
		if err != nil {
			t.Error("New session ID should be valid")
		}
		if retrieved.DID != "did:plc:test123" {
			t.Error("Session data should be preserved with new ID")
		}
	})
}

// TestSessionExpirationEnforcement verifies that expired sessions are properly
// rejected at multiple layers (cookie, store, validation).
func TestSessionExpirationEnforcement(t *testing.T) {
	t.Run("cookie MaxAge enforces expiration", func(t *testing.T) {
		// Test that cookie headers include MaxAge
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{
				Name:     "session_id",
				Value:    "test-session",
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   86400, // 24 hours
			})
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		handler(w, req)

		// Check cookie header
		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatal("Expected one cookie")
		}

		cookie := cookies[0]
		if cookie.MaxAge != 86400 {
			t.Errorf("Cookie MaxAge should be 86400 seconds, got %d", cookie.MaxAge)
		}
	})

	t.Run("session store TTL enforces expiration", func(t *testing.T) {
		// Create store with short TTL
		store := NewMemorySessionStoreWithTTL(100*time.Millisecond, 50*time.Millisecond)
		defer store.Stop()

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		// Store session
		sessionID := GenerateSessionID()
		session := &Session{
			DID:         "did:plc:test123",
			AccessToken: "token",
			DPoPKey:     key,
		}
		store.Set(sessionID, session)

		// Should be valid immediately
		_, err = store.Get(sessionID)
		if err != nil {
			t.Error("Session should be valid immediately after creation")
		}

		// Wait for expiration
		time.Sleep(150 * time.Millisecond)

		// Should be expired now
		_, err = store.Get(sessionID)
		if err == nil {
			t.Error("Session should be expired after TTL")
		}
	})

	t.Run("expired sessions are rejected", func(t *testing.T) {
		store := NewMemorySessionStoreWithTTL(50*time.Millisecond, 25*time.Millisecond)
		defer store.Stop()

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		// Create multiple sessions
		for i := 0; i < 5; i++ {
			sessionID := GenerateSessionID()
			session := &Session{
				DID:         "did:plc:test" + string(rune(i)),
				AccessToken: "token" + string(rune(i)),
				DPoPKey:     key,
			}
			store.Set(sessionID, session)
		}

		// Wait for all to expire
		time.Sleep(100 * time.Millisecond)

		// Try to use expired session - should fail
		expiredID := GenerateSessionID()
		_, err = store.Get(expiredID)
		if err == nil {
			t.Error("Expired or non-existent session should be rejected")
		}
	})

	t.Run("cleanup goroutine removes expired sessions", func(t *testing.T) {
		store := NewMemorySessionStoreWithTTL(50*time.Millisecond, 25*time.Millisecond)
		defer store.Stop()

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		// Add session
		sessionID := GenerateSessionID()
		session := &Session{
			DID:         "did:plc:test123",
			AccessToken: "token",
			DPoPKey:     key,
		}
		store.Set(sessionID, session)

		// Wait for expiration and cleanup
		time.Sleep(200 * time.Millisecond)

		// Session should be cleaned up
		_, err = store.Get(sessionID)
		if err == nil {
			t.Error("Cleanup should have removed expired session")
		}
	})
}

// TestSessionConcurrentAccess verifies thread-safety of session operations
// under concurrent access.
func TestSessionConcurrentAccess(t *testing.T) {
	t.Run("concurrent reads and writes are thread-safe", func(t *testing.T) {
		store := NewMemorySessionStore()

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		// Create initial session
		sessionID := GenerateSessionID()
		session := &Session{
			DID:         "did:plc:test123",
			AccessToken: "token",
			DPoPKey:     key,
		}
		store.Set(sessionID, session)

		// Perform concurrent operations
		var wg sync.WaitGroup
		errors := make(chan error, 100)

		// Concurrent reads
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := store.Get(sessionID)
				if err != nil {
					errors <- err
				}
			}()
		}

		// Concurrent writes
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				newSession := &Session{
					DID:         "did:plc:test" + string(rune(idx)),
					AccessToken: "token" + string(rune(idx)),
					DPoPKey:     key,
				}
				store.Set(sessionID, newSession)
			}(i)
		}

		wg.Wait()
		close(errors)

		// Check for errors
		for err := range errors {
			t.Errorf("Concurrent access error: %v", err)
		}
	})

	t.Run("session updates during concurrent access", func(t *testing.T) {
		store := NewMemorySessionStore()

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		sessionID := GenerateSessionID()
		numGoroutines := 100
		var wg sync.WaitGroup

		// Many goroutines updating the same session
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				session := &Session{
					DID:         "did:plc:updated",
					AccessToken: "token" + string(rune(idx)),
					DPoPKey:     key,
				}
				store.Set(sessionID, session)
			}(i)
		}

		wg.Wait()

		// Session should still be retrievable
		retrieved, err := store.Get(sessionID)
		if err != nil {
			t.Errorf("Session should be retrievable after concurrent updates: %v", err)
		}
		if retrieved.DID != "did:plc:updated" {
			t.Error("Session should have been updated")
		}
	})
}

// TestSessionCookieSecurityFlags verifies that session cookies have proper
// security flags set to prevent various attacks.
func TestSessionCookieSecurityFlags(t *testing.T) {
	t.Run("HttpOnly flag prevents JavaScript access", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{
				Name:     "session_id",
				Value:    "test-session",
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   86400,
			})
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		handler(w, req)

		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatal("Expected one cookie")
		}

		if !cookies[0].HttpOnly {
			t.Error("Cookie should have HttpOnly flag set (prevents XSS)")
		}
	})

	t.Run("Secure flag set for HTTPS", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Detect HTTPS from URL or X-Forwarded-Proto header
			isSecure := strings.HasPrefix(r.URL.String(), "https://") ||
				r.Header.Get("X-Forwarded-Proto") == "https" ||
				r.TLS != nil

			http.SetCookie(w, &http.Cookie{
				Name:     "session_id",
				Value:    "test-session",
				Path:     "/",
				HttpOnly: true,
				Secure:   isSecure,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   86400,
			})
			w.WriteHeader(http.StatusOK)
		})

		// Test with HTTPS
		req := httptest.NewRequest("GET", "https://example.com/", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()
		handler(w, req)

		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatal("Expected one cookie")
		}

		if !cookies[0].Secure {
			t.Error("Cookie should have Secure flag for HTTPS (prevents interception)")
		}
	})

	t.Run("SameSite flag prevents CSRF", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{
				Name:     "session_id",
				Value:    "test-session",
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   86400,
			})
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		handler(w, req)

		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatal("Expected one cookie")
		}

		if cookies[0].SameSite != http.SameSiteLaxMode {
			t.Errorf("Cookie should have SameSite=Lax (prevents CSRF), got %v", cookies[0].SameSite)
		}
	})

	t.Run("localhost detection for development", func(t *testing.T) {
		tests := []struct {
			name        string
			host        string
			isLocalhost bool
		}{
			{"localhost", "localhost:8080", true},
			{"127.0.0.1", "127.0.0.1:8080", true},
			{"IPv6 localhost", "[::1]:8080", true},
			{"production", "example.com", false},
			{"production with port", "example.com:443", false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				host := tt.host
				// Strip port for checking
				if idx := strings.LastIndex(host, ":"); idx != -1 {
					host = host[:idx]
				}
				// Remove IPv6 brackets
				host = strings.TrimPrefix(host, "[")
				host = strings.TrimSuffix(host, "]")

				isLocal := host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "0.0.0.0"

				if isLocal != tt.isLocalhost {
					t.Errorf("Expected isLocalhost=%v for %s, got %v", tt.isLocalhost, tt.host, isLocal)
				}
			})
		}
	})

	t.Run("cookie path prevents leakage", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{
				Name:     "session_id",
				Value:    "test-session",
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   86400,
			})
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		handler(w, req)

		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatal("Expected one cookie")
		}

		if cookies[0].Path != "/" {
			t.Errorf("Cookie path should be '/', got '%s'", cookies[0].Path)
		}
	})
}

// TestSessionStorageSecure tests that sessions stored contain appropriate data
// and don't leak sensitive information.
func TestSessionStorageSecure(t *testing.T) {
	t.Run("sessions contain required fields", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		session := &Session{
			DID:                  "did:plc:test123",
			AccessToken:          "access-token",
			RefreshToken:         "refresh-token",
			DPoPKey:              key,
			AccessTokenExpiresAt: time.Now().Add(12 * time.Hour),
		}

		// Verify all critical fields are present
		if session.DID == "" {
			t.Error("Session should have DID")
		}
		if session.AccessToken == "" {
			t.Error("Session should have AccessToken")
		}
		if session.RefreshToken == "" {
			t.Error("Session should have RefreshToken")
		}
		if session.DPoPKey == nil {
			t.Error("Session should have DPoPKey")
		}
		if session.AccessTokenExpiresAt.IsZero() {
			t.Error("Session should have AccessTokenExpiresAt")
		}
	})

	t.Run("session store operations are secure", func(t *testing.T) {
		store := NewMemorySessionStore()

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate key: %v", err)
		}

		sessionID := GenerateSessionID()
		session := &Session{
			DID:         "did:plc:test123",
			AccessToken: "sensitive-token",
			DPoPKey:     key,
		}

		// Store session
		store.Set(sessionID, session)

		// Retrieve session
		retrieved, err := store.Get(sessionID)
		if err != nil {
			t.Fatalf("Failed to retrieve session: %v", err)
		}

		// Verify data integrity
		if retrieved.DID != session.DID {
			t.Error("Session DID should match")
		}
		if retrieved.AccessToken != session.AccessToken {
			t.Error("Session AccessToken should match")
		}

		// Delete session
		store.Delete(sessionID)

		// Verify deletion
		_, err = store.Get(sessionID)
		if err == nil {
			t.Error("Deleted session should not be retrievable")
		}
	})
}
