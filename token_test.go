package bskyoauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

func TestIsAccessTokenExpired(t *testing.T) {
	tests := []struct {
		name           string
		expiresAt      time.Time
		buffer         time.Duration
		expectedExpired bool
	}{
		{
			name:           "token expired 1 hour ago",
			expiresAt:      time.Now().Add(-1 * time.Hour),
			buffer:         0,
			expectedExpired: true,
		},
		{
			name:           "token expires in 1 hour no buffer",
			expiresAt:      time.Now().Add(1 * time.Hour),
			buffer:         0,
			expectedExpired: false,
		},
		{
			name:           "token expires in 10 minutes with 15 minute buffer",
			expiresAt:      time.Now().Add(10 * time.Minute),
			buffer:         15 * time.Minute,
			expectedExpired: true,
		},
		{
			name:           "token expires in 30 minutes with 5 minute buffer",
			expiresAt:      time.Now().Add(30 * time.Minute),
			buffer:         5 * time.Minute,
			expectedExpired: false,
		},
		{
			name:           "no expiration time set",
			expiresAt:      time.Time{},
			buffer:         5 * time.Minute,
			expectedExpired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{
				AccessTokenExpiresAt: tt.expiresAt,
			}

			expired := session.IsAccessTokenExpired(tt.buffer)
			if expired != tt.expectedExpired {
				t.Errorf("expected expired=%v, got %v", tt.expectedExpired, expired)
			}
		})
	}
}

func TestIsRefreshTokenExpired(t *testing.T) {
	tests := []struct {
		name           string
		expiresAt      time.Time
		expectedExpired bool
	}{
		{
			name:           "refresh token expired",
			expiresAt:      time.Now().Add(-1 * time.Hour),
			expectedExpired: true,
		},
		{
			name:           "refresh token valid",
			expiresAt:      time.Now().Add(24 * time.Hour),
			expectedExpired: false,
		},
		{
			name:           "no expiration time set",
			expiresAt:      time.Time{},
			expectedExpired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{
				RefreshTokenExpiresAt: tt.expiresAt,
			}

			expired := session.IsRefreshTokenExpired()
			if expired != tt.expectedExpired {
				t.Errorf("expected expired=%v, got %v", tt.expectedExpired, expired)
			}
		})
	}
}

func TestTimeUntilAccessTokenExpiry(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expectZero bool
	}{
		{
			name:      "token expires in 1 hour",
			expiresAt: time.Now().Add(1 * time.Hour),
			expectZero: false,
		},
		{
			name:      "token already expired",
			expiresAt: time.Now().Add(-1 * time.Hour),
			expectZero: true,
		},
		{
			name:      "no expiration time set",
			expiresAt: time.Time{},
			expectZero: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{
				AccessTokenExpiresAt: tt.expiresAt,
			}

			duration := session.TimeUntilAccessTokenExpiry()

			if tt.expectZero {
				if duration != 0 {
					t.Errorf("expected zero duration, got %v", duration)
				}
			} else {
				if duration <= 0 {
					t.Errorf("expected positive duration, got %v", duration)
				}
				// Allow some tolerance for test execution time
				expected := time.Until(tt.expiresAt)
				if duration < expected-time.Second || duration > expected+time.Second {
					t.Errorf("expected duration ~%v, got %v", expected, duration)
				}
			}
		})
	}
}

func TestUpdateSession(t *testing.T) {
	store := NewMemorySessionStore()
	client := NewClientWithOptions(ClientOptions{
		BaseURL:      "http://localhost:8181",
		SessionStore: store,
	})

	// Create initial session
	dpopKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	session := &Session{
		DID:          "did:plc:test123",
		AccessToken:  "old_token",
		RefreshToken: "refresh_token",
		DPoPKey:      dpopKey,
		PDS:          "https://bsky.social",
		AccessTokenExpiresAt: time.Now().Add(1 * time.Hour),
	}

	sessionID := "test-session-id"
	err := client.SessionStore.Set(sessionID, session)
	if err != nil {
		t.Fatalf("failed to set initial session: %v", err)
	}

	// Update with new tokens
	newSession := &Session{
		DID:          "did:plc:test123",
		AccessToken:  "new_token",
		RefreshToken: "new_refresh_token",
		DPoPKey:      dpopKey,
		PDS:          "https://bsky.social",
		AccessTokenExpiresAt: time.Now().Add(2 * time.Hour),
	}

	err = client.UpdateSession(sessionID, newSession)
	if err != nil {
		t.Fatalf("failed to update session: %v", err)
	}

	// Verify update
	retrieved, err := client.GetSession(sessionID)
	if err != nil {
		t.Fatalf("failed to get updated session: %v", err)
	}

	if retrieved.AccessToken != "new_token" {
		t.Errorf("expected access token 'new_token', got '%s'", retrieved.AccessToken)
	}

	if retrieved.RefreshToken != "new_refresh_token" {
		t.Errorf("expected refresh token 'new_refresh_token', got '%s'", retrieved.RefreshToken)
	}
}

func TestRefreshToken_NoRefreshToken(t *testing.T) {
	client := NewClient("http://localhost:8181")

	dpopKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	session := &Session{
		DID:          "did:plc:test123",
		AccessToken:  "access_token",
		RefreshToken: "", // No refresh token
		DPoPKey:      dpopKey,
		PDS:          "https://bsky.social",
	}

	_, err := client.RefreshToken(context.Background(), session)
	if err == nil {
		t.Error("expected error when refresh token is missing")
	}

	if err.Error() != "no refresh token available" {
		t.Errorf("expected 'no refresh token available' error, got: %v", err)
	}
}

func TestRefreshToken_ExpiredRefreshToken(t *testing.T) {
	client := NewClient("http://localhost:8181")

	dpopKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	session := &Session{
		DID:                   "did:plc:test123",
		AccessToken:           "access_token",
		RefreshToken:          "refresh_token",
		RefreshTokenExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
		DPoPKey:               dpopKey,
		PDS:                   "https://bsky.social",
	}

	_, err := client.RefreshToken(context.Background(), session)
	if err == nil {
		t.Error("expected error when refresh token is expired")
	}

	if err.Error() != "refresh token expired" {
		t.Errorf("expected 'refresh token expired' error, got: %v", err)
	}
}
