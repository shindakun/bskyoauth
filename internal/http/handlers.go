package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Logger interface for HTTP operations
type Logger interface {
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// AuthFlow defines the interface for OAuth flow operations
type AuthFlow interface {
	StartAuthFlow(ctx context.Context, handle string) (*FlowState, error)
	CompleteAuthFlow(ctx context.Context, code, state, iss string) (*Session, error)
}

// FlowState represents the state of an OAuth flow
type FlowState struct {
	AuthURL string
}

// Session represents an authenticated user session
type Session struct {
	DID         string
	AccessToken string
}

// SessionStore defines the interface for session storage
type SessionStore interface {
	Set(sessionID string, session *Session) error
}

// Handlers provides HTTP handler implementations
type Handlers struct {
	AuthFlow          AuthFlow
	SessionStore      SessionStore
	LoggerGetter      func(context.Context) Logger
	ValidateHandle    func(string) error
	GenerateSessionID func() string
	GetClientMetadata func() map[string]interface{}
}

// ClientMetadata returns a handler that serves OAuth client metadata
func (h *Handlers) ClientMetadata() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(h.GetClientMetadata())
	}
}

// Login returns a handler that initiates the OAuth flow
func (h *Handlers) Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := h.LoggerGetter(r.Context())
		handle := r.URL.Query().Get("handle")
		if handle == "" {
			logger.Warn("login attempt with missing handle parameter")
			http.Error(w, "handle parameter required", http.StatusBadRequest)
			return
		}

		// Validate handle format
		if err := h.ValidateHandle(handle); err != nil {
			logger.Warn("login attempt with invalid handle",
				"handle", handle,
				"error", err)
			http.Error(w, fmt.Sprintf("invalid handle: %v", err), http.StatusBadRequest)
			return
		}

		flowState, err := h.AuthFlow.StartAuthFlow(r.Context(), handle)
		if err != nil {
			logger.Error("failed to start auth flow in LoginHandler",
				"handle", handle,
				"error", err)
			http.Error(w, "Failed to start auth flow: "+err.Error(), http.StatusInternalServerError)
			return
		}

		logger.Info("redirecting to OAuth authorization",
			"handle", handle)
		http.Redirect(w, r, flowState.AuthURL, http.StatusFound)
	}
}

// Callback returns a handler that completes the OAuth flow
func (h *Handlers) Callback(onSuccess func(w http.ResponseWriter, r *http.Request, sessionID string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := h.LoggerGetter(r.Context())

		// Check for error response first
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			errDesc := r.URL.Query().Get("error_description")
			logger.Warn("OAuth callback received error",
				"error", errParam,
				"description", errDesc)
			http.Error(w, "OAuth error: "+errParam+" - "+errDesc, http.StatusBadRequest)
			return
		}

		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		iss := r.URL.Query().Get("iss")

		if code == "" || state == "" {
			logger.Warn("OAuth callback missing required parameters",
				"query_string", r.URL.RawQuery)
			http.Error(w, "Missing code or state. Received params: "+r.URL.RawQuery, http.StatusBadRequest)
			return
		}

		session, err := h.AuthFlow.CompleteAuthFlow(r.Context(), code, state, iss)
		if err != nil {
			logger.Error("failed to complete auth flow in CallbackHandler",
				"error", err)
			http.Error(w, "Failed to complete auth flow: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Generate session ID and store
		sessionID := h.GenerateSessionID()
		if err := h.SessionStore.Set(sessionID, session); err != nil {
			logger.Error("failed to store session",
				"session_id", sessionID,
				"did", session.DID,
				"error", err)
			http.Error(w, "Failed to store session: "+err.Error(), http.StatusInternalServerError)
			return
		}

		logger.Info("OAuth callback completed successfully",
			"session_id", sessionID,
			"did", session.DID)

		onSuccess(w, r, sessionID)
	}
}
