package bskyoauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNewClient verifies basic client creation with defaults.
func TestNewClient(t *testing.T) {
	baseURL := "http://localhost:8181"
	client := NewClient(baseURL)

	if client == nil {
		t.Fatal("NewClient returned nil")
	}

	if client.BaseURL != baseURL {
		t.Errorf("BaseURL: expected %s, got %s", baseURL, client.BaseURL)
	}

	expectedClientID := baseURL + "/client-metadata.json"
	if client.ClientID != expectedClientID {
		t.Errorf("ClientID: expected %s, got %s", expectedClientID, client.ClientID)
	}

	expectedRedirectURI := baseURL + "/callback"
	if client.RedirectURI != expectedRedirectURI {
		t.Errorf("RedirectURI: expected %s, got %s", expectedRedirectURI, client.RedirectURI)
	}

	if client.ClientName != "Bluesky OAuth Client" {
		t.Errorf("ClientName: expected 'Bluesky OAuth Client', got %s", client.ClientName)
	}

	if len(client.Scopes) != 2 || client.Scopes[0] != "atproto" || client.Scopes[1] != "transition:generic" {
		t.Errorf("Scopes: expected ['atproto', 'transition:generic'], got %v", client.Scopes)
	}

	if client.SessionStore == nil {
		t.Error("SessionStore should be initialized with default store")
	}
}

// TestNewClientWithTrailingSlash verifies trailing slash is removed from BaseURL.
func TestNewClientWithTrailingSlash(t *testing.T) {
	baseURL := "http://localhost:8181/"
	client := NewClient(baseURL)

	expectedBaseURL := "http://localhost:8181"
	if client.BaseURL != expectedBaseURL {
		t.Errorf("BaseURL: expected %s, got %s", expectedBaseURL, client.BaseURL)
	}

	expectedClientID := "http://localhost:8181/client-metadata.json"
	if client.ClientID != expectedClientID {
		t.Errorf("ClientID: expected %s, got %s", expectedClientID, client.ClientID)
	}
}

// TestNewClientWithOptions verifies custom client configuration.
func TestNewClientWithOptions(t *testing.T) {
	customStore := NewMemorySessionStore()
	opts := ClientOptions{
		BaseURL:      "https://example.com",
		ClientName:   "Custom OAuth Client",
		Scopes:       []string{"custom:scope", "another:scope"},
		SessionStore: customStore,
	}

	client := NewClientWithOptions(opts)

	if client.BaseURL != "https://example.com" {
		t.Errorf("BaseURL: expected https://example.com, got %s", client.BaseURL)
	}

	if client.ClientName != "Custom OAuth Client" {
		t.Errorf("ClientName: expected 'Custom OAuth Client', got %s", client.ClientName)
	}

	if len(client.Scopes) != 2 || client.Scopes[0] != "custom:scope" {
		t.Errorf("Scopes: expected custom scopes, got %v", client.Scopes)
	}

	if client.SessionStore != customStore {
		t.Error("SessionStore: expected custom store to be used")
	}
}

// TestNewClientWithOptionsDefaults verifies defaults are applied when options are empty.
func TestNewClientWithOptionsDefaults(t *testing.T) {
	opts := ClientOptions{
		BaseURL: "http://localhost:3000",
		// ClientName, Scopes, SessionStore not provided
	}

	client := NewClientWithOptions(opts)

	if client.ClientName != "Bluesky OAuth Client" {
		t.Errorf("ClientName default: expected 'Bluesky OAuth Client', got %s", client.ClientName)
	}

	if len(client.Scopes) != 2 || client.Scopes[0] != "atproto" {
		t.Errorf("Scopes default: expected ['atproto', 'transition:generic'], got %v", client.Scopes)
	}

	if client.SessionStore == nil {
		t.Error("SessionStore default: should be initialized")
	}
}

// TestGetClientMetadata verifies client metadata structure.
func TestGetClientMetadata(t *testing.T) {
	client := NewClient("https://oauth.example.com")
	metadata := client.GetClientMetadata()

	// Verify required fields
	if metadata["client_id"] != "https://oauth.example.com/client-metadata.json" {
		t.Errorf("client_id: expected https://oauth.example.com/client-metadata.json, got %v", metadata["client_id"])
	}

	if metadata["client_name"] != "Bluesky OAuth Client" {
		t.Errorf("client_name: expected 'Bluesky OAuth Client', got %v", metadata["client_name"])
	}

	redirectURIs, ok := metadata["redirect_uris"].([]string)
	if !ok || len(redirectURIs) != 1 || redirectURIs[0] != "https://oauth.example.com/callback" {
		t.Errorf("redirect_uris: expected ['https://oauth.example.com/callback'], got %v", metadata["redirect_uris"])
	}

	if metadata["scope"] != "atproto transition:generic" {
		t.Errorf("scope: expected 'atproto transition:generic', got %v", metadata["scope"])
	}

	grantTypes, ok := metadata["grant_types"].([]string)
	if !ok || len(grantTypes) != 2 {
		t.Errorf("grant_types: expected 2 types, got %v", metadata["grant_types"])
	}

	if metadata["token_endpoint_auth_method"] != "none" {
		t.Errorf("token_endpoint_auth_method: expected 'none', got %v", metadata["token_endpoint_auth_method"])
	}

	if metadata["application_type"] != "web" {
		t.Errorf("application_type: expected 'web', got %v", metadata["application_type"])
	}

	if metadata["dpop_bound_access_tokens"] != true {
		t.Errorf("dpop_bound_access_tokens: expected true, got %v", metadata["dpop_bound_access_tokens"])
	}
}

// TestClientMetadataHandler verifies the HTTP handler for client metadata.
func TestClientMetadataHandler(t *testing.T) {
	client := NewClient("https://oauth.example.com")
	handler := client.ClientMetadataHandler()

	req := httptest.NewRequest("GET", "/client-metadata.json", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Status code: expected 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type: expected application/json, got %s", contentType)
	}

	// Verify JSON can be parsed
	var metadata map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&metadata)
	if err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	if metadata["client_id"] != "https://oauth.example.com/client-metadata.json" {
		t.Errorf("JSON client_id: expected https://oauth.example.com/client-metadata.json, got %v", metadata["client_id"])
	}
}

// TestGetSession verifies retrieving sessions through the client.
func TestGetSession(t *testing.T) {
	client := NewClient("http://localhost:8181")
	sessionID := "test-session-123"

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	session := &Session{
		DID:         "did:plc:test123",
		AccessToken: "token123",
		DPoPKey:     key,
	}

	// Store session
	err := client.SessionStore.Set(sessionID, session)
	if err != nil {
		t.Fatalf("Failed to store session: %v", err)
	}

	// Retrieve via Client.GetSession
	retrieved, err := client.GetSession(sessionID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	if retrieved.DID != session.DID {
		t.Errorf("DID: expected %s, got %s", session.DID, retrieved.DID)
	}

	if retrieved.AccessToken != session.AccessToken {
		t.Errorf("AccessToken: expected %s, got %s", session.AccessToken, retrieved.AccessToken)
	}
}

// TestGetSessionNotFound verifies error handling for non-existent sessions.
func TestGetSessionNotFound(t *testing.T) {
	client := NewClient("http://localhost:8181")

	_, err := client.GetSession("non-existent")
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound, got %v", err)
	}
}

// TestDeleteSession verifies session deletion through the client.
func TestDeleteSession(t *testing.T) {
	client := NewClient("http://localhost:8181")
	sessionID := "test-session-delete"

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	session := &Session{
		DID:         "did:plc:test123",
		AccessToken: "token123",
		DPoPKey:     key,
	}

	// Store session
	client.SessionStore.Set(sessionID, session)

	// Delete via Client.DeleteSession
	err := client.DeleteSession(sessionID)
	if err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}

	// Verify it's gone
	_, err = client.GetSession(sessionID)
	if err != ErrSessionNotFound {
		t.Errorf("Expected ErrSessionNotFound after delete, got %v", err)
	}
}

// TestClientWithCustomSessionStore verifies using a custom session store.
func TestClientWithCustomSessionStore(t *testing.T) {
	customStore := NewMemorySessionStore()

	// Pre-populate the custom store
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	session := &Session{
		DID:         "did:plc:prepopulated",
		AccessToken: "prepopulated-token",
		DPoPKey:     key,
	}
	customStore.Set("prepopulated-id", session)

	// Create client with custom store
	client := NewClientWithOptions(ClientOptions{
		BaseURL:      "http://localhost:8181",
		SessionStore: customStore,
	})

	// Verify client can access pre-populated session
	retrieved, err := client.GetSession("prepopulated-id")
	if err != nil {
		t.Fatalf("Failed to retrieve prepopulated session: %v", err)
	}

	if retrieved.DID != "did:plc:prepopulated" {
		t.Errorf("Expected prepopulated DID, got %s", retrieved.DID)
	}
}

// TestClientMultipleSessions verifies managing multiple sessions.
func TestClientMultipleSessions(t *testing.T) {
	client := NewClient("http://localhost:8181")

	// Create multiple sessions
	sessionCount := 5
	sessionIDs := make([]string, sessionCount)

	for i := 0; i < sessionCount; i++ {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		sessionID := GenerateSessionID()
		sessionIDs[i] = sessionID

		session := &Session{
			DID:         "did:plc:user" + string(rune(i)),
			AccessToken: "token-" + string(rune(i)),
			DPoPKey:     key,
		}

		err := client.SessionStore.Set(sessionID, session)
		if err != nil {
			t.Fatalf("Failed to store session %d: %v", i, err)
		}
	}

	// Verify all sessions can be retrieved
	for i, sessionID := range sessionIDs {
		session, err := client.GetSession(sessionID)
		if err != nil {
			t.Errorf("Failed to retrieve session %d: %v", i, err)
		}

		expectedDID := "did:plc:user" + string(rune(i))
		if session.DID != expectedDID {
			t.Errorf("Session %d: expected DID %s, got %s", i, expectedDID, session.DID)
		}
	}

	// Delete one session
	err := client.DeleteSession(sessionIDs[2])
	if err != nil {
		t.Fatalf("Failed to delete session: %v", err)
	}

	// Verify it's deleted but others remain
	_, err = client.GetSession(sessionIDs[2])
	if err != ErrSessionNotFound {
		t.Error("Expected session 2 to be deleted")
	}

	_, err = client.GetSession(sessionIDs[0])
	if err != nil {
		t.Error("Expected session 0 to still exist")
	}
}

// TestClientURLConstruction verifies URL construction for different base URLs.
func TestClientURLConstruction(t *testing.T) {
	testCases := []struct {
		baseURL          string
		expectedClientID string
		expectedRedirect string
	}{
		{
			baseURL:          "http://localhost:8181",
			expectedClientID: "http://localhost:8181/client-metadata.json",
			expectedRedirect: "http://localhost:8181/callback",
		},
		{
			baseURL:          "https://oauth.example.com",
			expectedClientID: "https://oauth.example.com/client-metadata.json",
			expectedRedirect: "https://oauth.example.com/callback",
		},
		{
			baseURL:          "https://oauth.example.com:8443",
			expectedClientID: "https://oauth.example.com:8443/client-metadata.json",
			expectedRedirect: "https://oauth.example.com:8443/callback",
		},
		{
			baseURL:          "http://192.168.1.100:3000",
			expectedClientID: "http://192.168.1.100:3000/client-metadata.json",
			expectedRedirect: "http://192.168.1.100:3000/callback",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.baseURL, func(t *testing.T) {
			client := NewClient(tc.baseURL)

			if client.ClientID != tc.expectedClientID {
				t.Errorf("ClientID: expected %s, got %s", tc.expectedClientID, client.ClientID)
			}

			if client.RedirectURI != tc.expectedRedirect {
				t.Errorf("RedirectURI: expected %s, got %s", tc.expectedRedirect, client.RedirectURI)
			}
		})
	}
}

// TestClientScopesCustomization verifies custom scopes are respected.
func TestClientScopesCustomization(t *testing.T) {
	customScopes := []string{"read", "write", "admin"}

	client := NewClientWithOptions(ClientOptions{
		BaseURL: "http://localhost:8181",
		Scopes:  customScopes,
	})

	if len(client.Scopes) != len(customScopes) {
		t.Errorf("Expected %d scopes, got %d", len(customScopes), len(client.Scopes))
	}

	for i, scope := range customScopes {
		if client.Scopes[i] != scope {
			t.Errorf("Scope %d: expected %s, got %s", i, scope, client.Scopes[i])
		}
	}
}

// TestClientNameCustomization verifies custom client name is respected.
func TestClientNameCustomization(t *testing.T) {
	customName := "My Awesome Bluesky App"

	client := NewClientWithOptions(ClientOptions{
		BaseURL:    "http://localhost:8181",
		ClientName: customName,
	})

	if client.ClientName != customName {
		t.Errorf("ClientName: expected %s, got %s", customName, client.ClientName)
	}

	// Verify it appears in metadata
	metadata := client.GetClientMetadata()
	if metadata["client_name"] != customName {
		t.Errorf("Metadata client_name: expected %s, got %v", customName, metadata["client_name"])
	}
}

// TestErrNoSession verifies the ErrNoSession error constant exists.
func TestErrNoSession(t *testing.T) {
	if ErrNoSession == nil {
		t.Error("ErrNoSession should not be nil")
	}

	if ErrNoSession.Error() != "no valid session" {
		t.Errorf("ErrNoSession message: expected 'no valid session', got %s", ErrNoSession.Error())
	}
}

// TestClientMetadataJSONStructure verifies the exact JSON structure.
func TestClientMetadataJSONStructure(t *testing.T) {
	client := NewClient("https://test.example.com")
	handler := client.ClientMetadataHandler()

	req := httptest.NewRequest("GET", "/client-metadata.json", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	var metadata map[string]interface{}
	json.NewDecoder(w.Body).Decode(&metadata)

	// Verify all required OAuth fields are present
	requiredFields := []string{
		"client_id",
		"client_name",
		"redirect_uris",
		"scope",
		"grant_types",
		"response_types",
		"token_endpoint_auth_method",
		"application_type",
		"dpop_bound_access_tokens",
	}

	for _, field := range requiredFields {
		if _, exists := metadata[field]; !exists {
			t.Errorf("Required field missing from metadata: %s", field)
		}
	}
}

// TestClientBaseURLEdgeCases verifies edge cases in BaseURL handling.
func TestClientBaseURLEdgeCases(t *testing.T) {
	testCases := []struct {
		name        string
		inputURL    string
		expectedURL string
	}{
		{
			name:        "No trailing slash",
			inputURL:    "http://localhost:8181",
			expectedURL: "http://localhost:8181",
		},
		{
			name:        "Single trailing slash",
			inputURL:    "http://localhost:8181/",
			expectedURL: "http://localhost:8181",
		},
		{
			name:        "HTTPS",
			inputURL:    "https://example.com",
			expectedURL: "https://example.com",
		},
		{
			name:        "With port and trailing slash",
			inputURL:    "http://localhost:3000/",
			expectedURL: "http://localhost:3000",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := NewClient(tc.inputURL)
			if client.BaseURL != tc.expectedURL {
				t.Errorf("BaseURL: expected %s, got %s", tc.expectedURL, client.BaseURL)
			}
		})
	}
}

// TestClientSessionStoreIsolation verifies each client has independent session store.
func TestClientSessionStoreIsolation(t *testing.T) {
	client1 := NewClient("http://localhost:8181")
	client2 := NewClient("http://localhost:8282")

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sessionID := "shared-id"

	// Store in client1
	session1 := &Session{
		DID:         "did:plc:client1",
		AccessToken: "token1",
		DPoPKey:     key,
	}
	client1.SessionStore.Set(sessionID, session1)

	// Client2 should not see client1's session
	_, err := client2.GetSession(sessionID)
	if err != ErrSessionNotFound {
		t.Error("Expected client2 to not see client1's session")
	}

	// Store in client2
	session2 := &Session{
		DID:         "did:plc:client2",
		AccessToken: "token2",
		DPoPKey:     key,
	}
	client2.SessionStore.Set(sessionID, session2)

	// Each client should see their own session
	retrieved1, _ := client1.GetSession(sessionID)
	if retrieved1.DID != "did:plc:client1" {
		t.Error("Client1 session corrupted")
	}

	retrieved2, _ := client2.GetSession(sessionID)
	if retrieved2.DID != "did:plc:client2" {
		t.Error("Client2 session corrupted")
	}
}

// TestApplicationTypeDefault verifies default application_type is "web".
func TestApplicationTypeDefault(t *testing.T) {
	client := NewClient("https://example.com")

	if client.ApplicationType != ApplicationTypeWeb {
		t.Errorf("Expected default ApplicationType to be %q, got %q", ApplicationTypeWeb, client.ApplicationType)
	}

	metadata := client.GetClientMetadata()
	if metadata["application_type"] != "web" {
		t.Errorf("Expected metadata application_type to be 'web', got %v", metadata["application_type"])
	}
}

// TestApplicationTypeWeb verifies explicit web application type.
func TestApplicationTypeWeb(t *testing.T) {
	client := NewClientWithOptions(ClientOptions{
		BaseURL:         "https://example.com",
		ApplicationType: ApplicationTypeWeb,
	})

	if client.ApplicationType != ApplicationTypeWeb {
		t.Errorf("Expected ApplicationType to be %q, got %q", ApplicationTypeWeb, client.ApplicationType)
	}

	metadata := client.GetClientMetadata()
	if metadata["application_type"] != "web" {
		t.Errorf("Expected metadata application_type to be 'web', got %v", metadata["application_type"])
	}
}

// TestApplicationTypeNative verifies native application type.
func TestApplicationTypeNative(t *testing.T) {
	client := NewClientWithOptions(ClientOptions{
		BaseURL:         "myapp://oauth",
		ApplicationType: ApplicationTypeNative,
	})

	if client.ApplicationType != ApplicationTypeNative {
		t.Errorf("Expected ApplicationType to be %q, got %q", ApplicationTypeNative, client.ApplicationType)
	}

	metadata := client.GetClientMetadata()
	if metadata["application_type"] != "native" {
		t.Errorf("Expected metadata application_type to be 'native', got %v", metadata["application_type"])
	}
}

// TestApplicationTypeInvalid verifies invalid application_type defaults to "web" with warning.
func TestApplicationTypeInvalid(t *testing.T) {
	client := NewClientWithOptions(ClientOptions{
		BaseURL:         "https://example.com",
		ApplicationType: "invalid_type",
	})

	// Should default to web
	if client.ApplicationType != ApplicationTypeWeb {
		t.Errorf("Expected invalid ApplicationType to default to %q, got %q", ApplicationTypeWeb, client.ApplicationType)
	}

	metadata := client.GetClientMetadata()
	if metadata["application_type"] != "web" {
		t.Errorf("Expected metadata application_type to default to 'web', got %v", metadata["application_type"])
	}
}

// TestApplicationTypeEmpty verifies empty application_type defaults to "web".
func TestApplicationTypeEmpty(t *testing.T) {
	client := NewClientWithOptions(ClientOptions{
		BaseURL:         "https://example.com",
		ApplicationType: "",
	})

	if client.ApplicationType != ApplicationTypeWeb {
		t.Errorf("Expected empty ApplicationType to default to %q, got %q", ApplicationTypeWeb, client.ApplicationType)
	}

	metadata := client.GetClientMetadata()
	if metadata["application_type"] != "web" {
		t.Errorf("Expected metadata application_type to default to 'web', got %v", metadata["application_type"])
	}
}

// TestApplicationTypeConstants verifies constant values.
func TestApplicationTypeConstants(t *testing.T) {
	if ApplicationTypeWeb != "web" {
		t.Errorf("Expected ApplicationTypeWeb constant to be 'web', got %q", ApplicationTypeWeb)
	}

	if ApplicationTypeNative != "native" {
		t.Errorf("Expected ApplicationTypeNative constant to be 'native', got %q", ApplicationTypeNative)
	}
}
