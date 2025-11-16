package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/api/bsky"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/xrpc"
	"golang.org/x/time/rate"

	"github.com/shindakun/bskyoauth"
)

// getEnvInt returns an integer environment variable or default value.
func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			return parsed
		}
		log.Printf("Warning: Invalid %s value '%s', using default: %d", key, val, defaultVal)
	}
	return defaultVal
}

// getRateLimitConfig parses "requests/sec,burst" format (e.g., "5,10").
func getRateLimitConfig(key string, defaultReqSec float64, defaultBurst int) (float64, int) {
	if val := os.Getenv(key); val != "" {
		parts := strings.Split(val, ",")
		if len(parts) == 2 {
			reqSec, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
			burst, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil && reqSec > 0 && burst > 0 {
				return reqSec, burst
			}
		}
		log.Printf("Warning: Invalid %s format '%s', using defaults: %.0f,%d", key, val, defaultReqSec, defaultBurst)
	}
	return defaultReqSec, defaultBurst
}

func main() {
	// Load configuration from environment variables
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8182"
	}

	serverPort := os.Getenv("SERVER_PORT")
	if serverPort == "" {
		serverPort = "8182"
	}

	sessionTimeoutDays := getEnvInt("SESSION_TIMEOUT_DAYS", 30)
	authReqSec, authBurst := getRateLimitConfig("RATE_LIMIT_AUTH", 5, 10)
	apiReqSec, apiBurst := getRateLimitConfig("RATE_LIMIT_API", 10, 20)

	// Configure structured logging based on environment
	logger := bskyoauth.NewLoggerFromEnv(baseURL)
	bskyoauth.SetLogger(logger)

	// Security check: warn if not using HTTPS in non-local environments
	if !strings.HasPrefix(baseURL, "https://") && !strings.Contains(baseURL, "localhost") && !strings.Contains(baseURL, "127.0.0.1") {
		log.Println("WARNING: BASE_URL is not using HTTPS!")
		log.Println("OAuth flows over HTTP expose credentials to interception.")
		log.Println("HTTPS is REQUIRED for production deployments.")
	}

	// Create OAuth client with chat scope
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	client := bskyoauth.NewClientWithOptions(bskyoauth.ClientOptions{
		BaseURL:    baseURL,
		HTTPClient: httpClient,
		Scopes:     []string{"atproto", "transition:generic", "transition:chat.bsky"},
	})

	// Create rate limiters
	authLimiter := bskyoauth.NewRateLimiter(rate.Limit(authReqSec), authBurst)
	authLimiter.StartCleanup(5*time.Minute, 10*time.Minute)

	apiLimiter := bskyoauth.NewRateLimiter(rate.Limit(apiReqSec), apiBurst)
	apiLimiter.StartCleanup(5*time.Minute, 10*time.Minute)

	// Set up HTTP handlers with rate limiting
	mux := http.NewServeMux()
	mux.HandleFunc("/", homeHandler(client))
	mux.HandleFunc("/client-metadata.json", client.ClientMetadataHandler())
	mux.HandleFunc("/login", authLimiter.Middleware(loginHandler(client)))
	mux.HandleFunc("/callback", authLimiter.Middleware(client.CallbackHandler(callbackSuccessHandler(sessionTimeoutDays))))
	mux.HandleFunc("/profile", apiLimiter.Middleware(profileHandler(client)))
	mux.HandleFunc("/logout", logoutHandler(client))

	// Apply security headers middleware
	handler := bskyoauth.SecurityHeadersMiddleware()(mux)

	// Display configuration
	log.Printf("Chat Demo Server starting on :%s", serverPort)
	log.Println("Base URL:", baseURL)
	log.Println("OAuth Scopes: atproto, transition:generic, transition:chat.bsky")
	if strings.HasPrefix(baseURL, "https://") {
		log.Println("Using HTTPS - secure configuration")
	}

	log.Printf("Rate limiting enabled:")
	log.Printf("  - Auth endpoints: %.0f req/s (burst: %d)", authReqSec, authBurst)
	log.Printf("  - API endpoints: %.0f req/s (burst: %d)", apiReqSec, apiBurst)
	log.Printf("Session timeout: %d days", sessionTimeoutDays)

	// Configure HTTP server with timeouts
	server := &http.Server{
		Addr:         ":" + serverPort,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}

// checkAndRefreshToken checks if the access token is expired and refreshes it if needed.
func checkAndRefreshToken(client *bskyoauth.Client, sessionID string, session *bskyoauth.Session, r *http.Request) (*bskyoauth.Session, error) {
	if session.IsAccessTokenExpired(5 * time.Minute) {
		log.Printf("Access token expired or expiring soon, attempting refresh for session: %s", sessionID)

		requestID := bskyoauth.GenerateRequestID()
		ctx := bskyoauth.WithRequestID(r.Context(), requestID)

		newSession, err := client.RefreshToken(ctx, session)
		if err != nil {
			log.Printf("[%s] Token refresh failed: %v", requestID, err)
			return nil, err
		}

		err = client.UpdateSession(sessionID, newSession)
		if err != nil {
			log.Printf("[%s] Failed to update session after refresh: %v", requestID, err)
			return nil, err
		}

		log.Printf("[%s] Token refresh successful for session: %s", requestID, sessionID)
		return newSession, nil
	}

	return session, nil
}

func homeHandler(client *bskyoauth.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID, err := r.Cookie("session_id")

		html := `<!DOCTYPE html>
<html>
<head>
	<title>Bluesky Chat OAuth Demo</title>
	<style>
		body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
		h1 { color: #0066cc; }
		.info { background: #f0f8ff; padding: 15px; border-radius: 5px; margin: 20px 0; }
		.scope { font-family: monospace; background: #e0e0e0; padding: 2px 5px; border-radius: 3px; }
		button, a.button {
			background: #0066cc;
			color: white;
			padding: 10px 20px;
			border: none;
			border-radius: 5px;
			cursor: pointer;
			text-decoration: none;
			display: inline-block;
			margin: 5px;
		}
		button:hover, a.button:hover { background: #0052a3; }
		input[type="text"] {
			padding: 10px;
			width: 300px;
			border: 1px solid #ccc;
			border-radius: 5px;
		}
	</style>
</head>
<body>
	<h1>Bluesky Chat OAuth Demo</h1>
	<div class="info">
		<p><strong>This demo uses the chat scope:</strong></p>
		<p>OAuth Scopes: <span class="scope">atproto</span> <span class="scope">transition:generic</span> <span class="scope">transition:chat.bsky</span></p>
		<p>It demonstrates how to request additional scopes and use XRPC to fetch user profile data.</p>
	</div>`

		if err == nil {
			session, err := client.GetSession(sessionID.Value)
			if err == nil && session != nil {
				html += fmt.Sprintf(`
	<p>Logged in as: <strong>%s</strong></p>
	<div>
		<a href="/profile" class="button">View My Profile (XRPC)</a>
		<a href="/logout" class="button">Logout</a>
	</div>`, session.DID)
			} else {
				html += loginForm()
			}
		} else {
			html += loginForm()
		}

		html += `</body></html>`
		w.Header().Set("Content-Type", "text/html")
		if _, err := w.Write([]byte(html)); err != nil {
			log.Printf("Error writing response: %v", err)
		}
	}
}

func loginForm() string {
	return `
	<h2>Login to Bluesky</h2>
	<form action="/login" method="get">
		<input type="text" name="handle" placeholder="your-handle.bsky.social" required>
		<button type="submit">Login with Bluesky</button>
	</form>`
}

func loginHandler(client *bskyoauth.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := bskyoauth.GenerateRequestID()
		ctx := bskyoauth.WithRequestID(r.Context(), requestID)

		handle := r.URL.Query().Get("handle")
		if handle == "" {
			http.Error(w, "handle parameter required", http.StatusBadRequest)
			return
		}

		// Validate handle format before attempting auth flow
		if err := bskyoauth.ValidateHandle(handle); err != nil {
			log.Printf("[%s] Invalid handle: %s - %v", requestID, handle, err)
			http.Error(w, fmt.Sprintf("invalid handle: %v", err), http.StatusBadRequest)
			return
		}

		log.Printf("[%s] Starting auth flow for handle: %s", requestID, handle)

		flowState, err := client.StartAuthFlow(ctx, handle)
		if err != nil {
			log.Printf("[%s] Failed to start auth flow: %v", requestID, err)
			http.Error(w, "Failed to start auth flow: "+err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("[%s] Redirecting to: %s", requestID, flowState.AuthURL)
		http.Redirect(w, r, flowState.AuthURL, http.StatusFound)
	}
}

func callbackSuccessHandler(sessionTimeoutDays int) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, sessionID string) {
		requestID := bskyoauth.GenerateRequestID()
		log.Printf("[%s] OAuth callback successful, session: %s", requestID, sessionID)

		baseURL := os.Getenv("BASE_URL")
		if baseURL == "" {
			baseURL = "http://localhost:8182"
		}
		isSecure := strings.HasPrefix(baseURL, "https://")

		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			Secure:   isSecure,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   sessionTimeoutDays * 86400,
		})

		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func profileHandler(client *bskyoauth.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID, err := r.Cookie("session_id")
		if err != nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		session, err := client.GetSession(sessionID.Value)
		if err != nil || session == nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		// Check and refresh token if needed
		session, err = checkAndRefreshToken(client, sessionID.Value, session, r)
		if err != nil {
			log.Printf("Token refresh failed, redirecting to login: %v", err)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		// Get the user's profile using XRPC
		profile, err := getProfile(r.Context(), session)
		if err != nil {
			http.Error(w, "Failed to get profile: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Display profile as HTML
		renderProfilePage(w, profile)
	}
}

// getProfile fetches the user's profile using XRPC with app.bsky.actor.getProfile
func getProfile(ctx context.Context, session *bskyoauth.Session) (*bsky.ActorDefs_ProfileViewDetailed, error) {
	log.Printf("Fetching profile for DID: %s", session.DID)

	// Resolve PDS endpoint for the user
	dir := identity.DefaultDirectory()
	atid, err := syntax.ParseAtIdentifier(session.DID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DID: %w", err)
	}

	ident, err := dir.Lookup(ctx, *atid)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup identity: %w", err)
	}

	pdsHost := ident.PDSEndpoint()

	// Create DPoP transport
	transport := bskyoauth.NewDPoPTransport(
		http.DefaultTransport,
		session.DPoPKey,
		session.AccessToken,
		session.DPoPNonce,
	)

	httpClient := &http.Client{
		Transport: transport,
	}

	xrpcClient := &xrpc.Client{
		Host:   pdsHost,
		Client: httpClient,
	}

	// Call app.bsky.actor.getProfile
	output, err := bsky.ActorGetProfile(ctx, xrpcClient, session.DID)
	if err != nil {
		return nil, fmt.Errorf("failed to get profile: %w", err)
	}

	// Update session with the latest nonce if available
	if nonceGetter, ok := transport.(interface{ GetNonce() string }); ok {
		session.DPoPNonce = nonceGetter.GetNonce()
	}

	log.Printf("Successfully fetched profile for: %s", output.Handle)
	return output, nil
}

func renderProfilePage(w http.ResponseWriter, profile *bsky.ActorDefs_ProfileViewDetailed) {
	// Convert profile to JSON for display
	profileJSON, _ := json.MarshalIndent(profile, "", "  ")

	html := `<!DOCTYPE html>
<html>
<head>
	<title>Profile - Bluesky Chat OAuth Demo</title>
	<style>
		body { font-family: Arial, sans-serif; max-width: 1000px; margin: 50px auto; padding: 20px; }
		h1 { color: #0066cc; }
		.profile-header {
			background: #f0f8ff;
			padding: 20px;
			border-radius: 10px;
			margin: 20px 0;
			display: flex;
			align-items: center;
			gap: 20px;
		}
		.profile-avatar {
			width: 80px;
			height: 80px;
			border-radius: 50%;
			object-fit: cover;
		}
		.profile-info h2 { margin: 0 0 5px 0; }
		.profile-info .handle { color: #666; }
		.profile-stats {
			display: flex;
			gap: 20px;
			margin: 20px 0;
		}
		.stat {
			background: #e8f4f8;
			padding: 15px;
			border-radius: 5px;
			text-align: center;
		}
		.stat-value { font-size: 24px; font-weight: bold; color: #0066cc; }
		.stat-label { font-size: 14px; color: #666; }
		.profile-json {
			background: #f5f5f5;
			padding: 20px;
			border-radius: 5px;
			overflow-x: auto;
			margin: 20px 0;
		}
		pre { margin: 0; font-size: 12px; }
		.actions { margin: 20px 0; }
		.actions a {
			background: #0066cc;
			color: white;
			padding: 10px 20px;
			text-decoration: none;
			border-radius: 5px;
			display: inline-block;
		}
		.actions a:hover { background: #0052a3; }
	</style>
</head>
<body>
	<h1>User Profile</h1>

	<div class="profile-header">`

	if profile.Avatar != nil && *profile.Avatar != "" {
		html += fmt.Sprintf(`
		<img src="%s" alt="Avatar" class="profile-avatar">`, *profile.Avatar)
	}

	displayName := profile.Handle
	if profile.DisplayName != nil && *profile.DisplayName != "" {
		displayName = *profile.DisplayName
	}

	html += fmt.Sprintf(`
		<div class="profile-info">
			<h2>%s</h2>
			<p class="handle">@%s</p>`, displayName, profile.Handle)

	if profile.Description != nil && *profile.Description != "" {
		html += fmt.Sprintf(`
			<p>%s</p>`, *profile.Description)
	}

	html += `
		</div>
	</div>

	<div class="profile-stats">`

	if profile.FollowersCount != nil {
		html += fmt.Sprintf(`
		<div class="stat">
			<div class="stat-value">%d</div>
			<div class="stat-label">Followers</div>
		</div>`, *profile.FollowersCount)
	}

	if profile.FollowsCount != nil {
		html += fmt.Sprintf(`
		<div class="stat">
			<div class="stat-value">%d</div>
			<div class="stat-label">Following</div>
		</div>`, *profile.FollowsCount)
	}

	if profile.PostsCount != nil {
		html += fmt.Sprintf(`
		<div class="stat">
			<div class="stat-value">%d</div>
			<div class="stat-label">Posts</div>
		</div>`, *profile.PostsCount)
	}

	html += `
	</div>

	<h3>Raw Profile Data (XRPC Response)</h3>
	<div class="profile-json">
		<pre>` + string(profileJSON) + `</pre>
	</div>

	<div class="actions">
		<a href="/">← Back to Home</a>
	</div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func logoutHandler(client *bskyoauth.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID, err := r.Cookie("session_id")
		if err == nil {
			if err := client.DeleteSession(sessionID.Value); err != nil {
				log.Printf("Error deleting session %s: %v", sessionID.Value, err)
			}
		}

		baseURL := os.Getenv("BASE_URL")
		if baseURL == "" {
			baseURL = "http://localhost:8182"
		}
		isSecure := strings.HasPrefix(baseURL, "https://")

		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   isSecure,
			SameSite: http.SameSiteLaxMode,
		})

		http.Redirect(w, r, "/", http.StatusFound)
	}
}
