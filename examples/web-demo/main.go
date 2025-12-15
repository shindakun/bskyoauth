package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/shindakun/bskyoauth"
	"github.com/shindakun/bskyoauth/lexicon"
)

// getEnvInt returns an integer environment variable or default value.
// Logs a warning if the value is set but invalid.
func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if parsed, err := strconv.Atoi(val); err == nil {
			return parsed
		}
		log.Printf("⚠️  Warning: Invalid %s value '%s', using default: %d", key, val, defaultVal)
	}
	return defaultVal
}

// getRateLimitConfig parses "requests/sec,burst" format (e.g., "5,10").
// Returns default values if parsing fails or env var is not set.
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
		log.Printf("⚠️  Warning: Invalid %s format '%s' (expected 'req/sec,burst'), using defaults: %.0f,%d", key, val, defaultReqSec, defaultBurst)
	}
	return defaultReqSec, defaultBurst
}

// validateConfig checks configuration values and logs warnings for unusual settings.
func validateConfig(sessionTimeoutDays int, authReqSec, apiReqSec float64, authBurst, apiBurst int) {
	warnings := []string{}

	if sessionTimeoutDays < 1 || sessionTimeoutDays > 365 {
		warnings = append(warnings, fmt.Sprintf("SESSION_TIMEOUT_DAYS=%d is unusual (expected 1-365)", sessionTimeoutDays))
	}

	if authReqSec < 0.1 || authReqSec > 100 {
		warnings = append(warnings, fmt.Sprintf("RATE_LIMIT_AUTH requests/sec=%.1f is unusual (expected 0.1-100)", authReqSec))
	}

	if apiReqSec < 0.1 || apiReqSec > 1000 {
		warnings = append(warnings, fmt.Sprintf("RATE_LIMIT_API requests/sec=%.1f is unusual (expected 0.1-1000)", apiReqSec))
	}

	if authBurst < 1 || apiBurst < 1 {
		warnings = append(warnings, "Rate limit burst values must be positive")
	}

	if len(warnings) > 0 {
		log.Println("⚠️  Configuration warnings:")
		for _, w := range warnings {
			log.Printf("   - %s", w)
		}
	}
}

func main() {
	// Load configuration from environment variables
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8181"
	}

	serverPort := os.Getenv("SERVER_PORT")
	if serverPort == "" {
		serverPort = "8181"
	}

	sessionTimeoutDays := getEnvInt("SESSION_TIMEOUT_DAYS", 30)
	authReqSec, authBurst := getRateLimitConfig("RATE_LIMIT_AUTH", 5, 10)
	apiReqSec, apiBurst := getRateLimitConfig("RATE_LIMIT_API", 10, 20)

	// Validate configuration and log warnings for unusual values
	validateConfig(sessionTimeoutDays, authReqSec, apiReqSec, authBurst, apiBurst)

	// Configure structured logging based on environment
	logger := bskyoauth.NewLoggerFromEnv(baseURL)
	bskyoauth.SetLogger(logger)

	// Security check: warn if not using HTTPS in non-local environments
	if !strings.HasPrefix(baseURL, "https://") && !strings.Contains(baseURL, "localhost") && !strings.Contains(baseURL, "127.0.0.1") {
		log.Println("⚠️  WARNING: BASE_URL is not using HTTPS!")
		log.Println("⚠️  OAuth flows over HTTP expose credentials to interception.")
		log.Println("⚠️  HTTPS is REQUIRED for production deployments.")
		log.Println("⚠️  See README.md Security section for deployment guidance.")
	}

	// Create OAuth client with custom timeout configuration
	// For production, you might want shorter timeouts for faster failure detection
	httpClient := &http.Client{
		Timeout: 30 * time.Second, // Total request timeout
	}

	client := bskyoauth.NewClientWithOptions(bskyoauth.ClientOptions{
		BaseURL:    baseURL,
		HTTPClient: httpClient,
	})

	// Create rate limiters for different endpoint types
	// Auth endpoints (login/callback): Prevent brute force attacks
	authLimiter := bskyoauth.NewRateLimiter(rate.Limit(authReqSec), authBurst)
	authLimiter.StartCleanup(5*time.Minute, 10*time.Minute)

	// API endpoints: Normal usage rate limiting
	apiLimiter := bskyoauth.NewRateLimiter(rate.Limit(apiReqSec), apiBurst)
	apiLimiter.StartCleanup(5*time.Minute, 10*time.Minute)

	// Set up HTTP handlers with rate limiting
	mux := http.NewServeMux()
	mux.HandleFunc("/", homeHandler(client))
	mux.HandleFunc("/oauth-client-metadata.json", client.ClientMetadataHandler())
	mux.HandleFunc("/login", authLimiter.Middleware(client.LoginHandler()))
	mux.HandleFunc("/callback", authLimiter.Middleware(client.CallbackHandler(callbackSuccessHandler(sessionTimeoutDays))))
	mux.HandleFunc("/post", apiLimiter.Middleware(postHandler(client)))
	mux.HandleFunc("/create-record", apiLimiter.Middleware(createRecordHandler(client)))
	mux.HandleFunc("/put-record", apiLimiter.Middleware(putRecordHandler(client)))
	mux.HandleFunc("/list-records", apiLimiter.Middleware(listRecordsHandler(client)))
	mux.HandleFunc("/delete-record", apiLimiter.Middleware(deleteRecordHandler(client)))
	mux.HandleFunc("/get-record", apiLimiter.Middleware(getRecordHandler(client)))
	mux.HandleFunc("/logout", logoutHandler(client))

	// Apply security headers middleware
	handler := bskyoauth.SecurityHeadersMiddleware()(mux)

	// Display configuration
	log.Printf("Server starting on :%s", serverPort)
	log.Println("Base URL:", baseURL)
	if strings.HasPrefix(baseURL, "https://") {
		log.Println("✓ Using HTTPS - secure configuration")
	}

	// Show logging configuration
	if strings.Contains(baseURL, "localhost") || strings.Contains(baseURL, "127.0.0.1") {
		log.Println("✓ Structured logging enabled: Info level (text format)")
	} else {
		log.Println("✓ Structured logging enabled: Error level (JSON format)")
	}

	log.Println("✓ Rate limiting enabled:")
	log.Printf("  - Auth endpoints: %.0f req/s (burst: %d)", authReqSec, authBurst)
	log.Printf("  - API endpoints: %.0f req/s (burst: %d)", apiReqSec, apiBurst)
	log.Printf("✓ Session timeout: %d days", sessionTimeoutDays)
	log.Println("✓ Security headers enabled (auto-detects localhost)")
	log.Println("✓ HTTP timeouts configured:")
	log.Println("  - Client requests: 30s total timeout")
	log.Println("  - Server read: 15s, write: 15s, idle: 60s")

	// Configure HTTP server with timeouts to prevent resource exhaustion attacks
	server := &http.Server{
		Addr:         ":" + serverPort,
		Handler:      handler,
		ReadTimeout:  15 * time.Second, // Time to read request headers and body
		WriteTimeout: 15 * time.Second, // Time to write response
		IdleTimeout:  60 * time.Second, // Time to wait for next request when keep-alive is enabled
	}

	log.Fatal(server.ListenAndServe())
}

// checkAndRefreshToken checks if the access token is expired and refreshes it if needed.
// Returns the (potentially refreshed) session and any error.
func checkAndRefreshToken(client *bskyoauth.Client, sessionID string, session *bskyoauth.Session, r *http.Request) (*bskyoauth.Session, error) {
	// Check if token will expire in the next 5 minutes
	if session.IsAccessTokenExpired(5 * time.Minute) {
		log.Printf("Access token expired or expiring soon, attempting refresh for session: %s", sessionID)

		// Add request ID for logging correlation
		requestID := bskyoauth.GenerateRequestID()
		ctx := bskyoauth.WithRequestID(r.Context(), requestID)

		// Attempt to refresh the token
		newSession, err := client.RefreshToken(ctx, session)
		if err != nil {
			log.Printf("[%s] Token refresh failed: %v", requestID, err)
			return nil, err
		}

		// Update session in store
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

// extractRkeyFromURI extracts the rkey (record key) from an AT URI
// Example: "at://did:plc:abc123/com.demo.bskyoauth/3k7qxyz..." -> "3k7qxyz..."
func extractRkeyFromURI(uri string) string {
	parts := strings.Split(uri, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

// renderRecordCreatedPage displays a success page after record creation
func renderRecordCreatedPage(w http.ResponseWriter, uri, rkey string) {
	html := `<!DOCTYPE html>
<html>
<head>
	<title>Record Created - Bluesky OAuth Demo</title>
	<style>
		body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
		.success { color: green; font-weight: bold; font-size: 1.2em; }
		.record-info {
			background: #f0f0f0;
			padding: 15px;
			margin: 10px 0;
			border-radius: 5px;
			font-family: monospace;
			word-break: break-all;
		}
		.rkey {
			font-size: 1.2em;
			color: #0066cc;
			user-select: all;
			padding: 5px;
			background: white;
			border-radius: 3px;
		}
		.actions { margin: 20px 0; }
		.actions a, .actions button {
			margin: 5px;
			padding: 10px 15px;
			text-decoration: none;
			background: #0066cc;
			color: white;
			border: none;
			border-radius: 5px;
			cursor: pointer;
			font-size: 14px;
		}
		.actions a:hover, .actions button:hover {
			background: #0052a3;
		}
		.actions form { display: inline; }
		hr { margin: 30px 0; }
	</style>
</head>
<body>
	<h1>✓ Record Created Successfully!</h1>

	<p class="success">Your com.demo.bskyoauth record has been created</p>

	<div class="record-info">
		<p><strong>Full AT URI:</strong><br>` + uri + `</p>
		<p><strong>Record Key (rkey):</strong><br>
		<span class="rkey">` + rkey + `</span></p>
	</div>

	<div class="actions">
		<a href="/get-record?rkey=` + rkey + `">View Record (JSON)</a>

		<form action="/delete-record" method="post">
			<input type="hidden" name="rkey" value="` + rkey + `">
			<button type="submit" onclick="return confirm('Delete this record?')">
				Delete Record
			</button>
		</form>

		<a href="/">Create Another Record</a>
	</div>

	<hr>
	<p><a href="/">← Back to Home</a></p>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

func homeHandler(client *bskyoauth.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID, err := r.Cookie("session_id")

		html := `<!DOCTYPE html>
<html>
<head><title>Bluesky OAuth Demo</title></head>
<body>
	<h1>Bluesky OAuth with DPoP</h1>`

		if err == nil {
			session, err := client.GetSession(sessionID.Value)
			if err == nil && session != nil {
				html += fmt.Sprintf(`
	<p>Logged in as: %s</p>
	<h2>Post to Bluesky</h2>
	<form action="/post" method="post">
		<textarea name="text" rows="4" cols="50" placeholder="What's happening?"></textarea><br>
		<button type="submit">Post to Bluesky</button>
	</form>
	<br>
	<h2>com.demo.bskyoauth Records</h2>
	<h3>Create Record</h3>
	<form action="/create-record" method="post">
		<textarea name="text" rows="3" cols="50" placeholder="Custom record text..."></textarea><br>
		<button type="submit">Create Record (auto-generated rkey)</button>
	</form>
	<br>
	<h3>Put Record (Create or Update at specific rkey)</h3>
	<form action="/put-record" method="post">
		<input type="text" name="rkey" placeholder="Record key (rkey)" required style="width: 300px;"><br>
		<textarea name="text" rows="3" cols="50" placeholder="Record text..."></textarea><br>
		<button type="submit">Put Record</button>
	</form>
	<br>
	<h3>List All Records</h3>
	<a href="/list-records" style="display: inline-block; padding: 10px 15px; background: #0066cc; color: white; text-decoration: none; border-radius: 5px;">View All Records</a>
	<br><br>
	<h3>Get / Delete Record</h3>
	<form action="/get-record" method="get" style="display: inline;">
		<input type="text" name="rkey" placeholder="Record key (rkey)" required>
		<button type="submit">Get Record (JSON)</button>
	</form>
	<br><br>
	<form action="/delete-record" method="post" style="display: inline;">
		<input type="text" name="rkey" placeholder="Record key (rkey)" required>
		<button type="submit">Delete Record</button>
	</form>
	<br><br>
	<a href="/logout">Logout</a>`, session.DID)
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
	<form action="/login" method="get">
		<input type="text" name="handle" placeholder="your-handle.bsky.social" required>
		<button type="submit">Login with Bluesky</button>
	</form>`
}

func callbackSuccessHandler(sessionTimeoutDays int) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, sessionID string) {
		// Add request ID for correlation
		requestID := bskyoauth.GenerateRequestID()
		log.Printf("[%s] OAuth callback successful, session: %s", requestID, sessionID)

		// Determine if we're running in secure mode (HTTPS)
		baseURL := os.Getenv("BASE_URL")
		if baseURL == "" {
			baseURL = "http://localhost:8181"
		}
		isSecure := strings.HasPrefix(baseURL, "https://")

		// Set session cookie with security enhancements
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,                       // Prevents JavaScript access
			Secure:   isSecure,                   // HTTPS only in production
			SameSite: http.SameSiteLaxMode,       // CSRF protection
			MaxAge:   sessionTimeoutDays * 86400, // Convert days to seconds
		})

		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func postHandler(client *bskyoauth.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

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
			// Refresh failed - redirect to login
			log.Printf("Token refresh failed, redirecting to login: %v", err)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		text := r.FormValue("text")
		if text == "" {
			http.Error(w, "Text is required", http.StatusBadRequest)
			return
		}

		// Validate post text
		if err := bskyoauth.ValidatePostText(text); err != nil {
			http.Error(w, fmt.Sprintf("Invalid post text: %v", err), http.StatusBadRequest)
			return
		}

		err = client.CreatePost(r.Context(), session, text)
		if err != nil {
			// Check if error is due to expired token
			if strings.Contains(err.Error(), "invalid_token") && strings.Contains(err.Error(), "401") {
				log.Printf("Token expired during CreatePost, attempting refresh for session: %s", sessionID.Value)

				// Attempt token refresh
				requestID := bskyoauth.GenerateRequestID()
				ctx := bskyoauth.WithRequestID(r.Context(), requestID)

				newSession, refreshErr := client.RefreshToken(ctx, session)
				if refreshErr != nil {
					log.Printf("[%s] Token refresh failed: %v", requestID, refreshErr)
					http.Error(w, "Session expired. Please log in again.", http.StatusUnauthorized)
					return
				}

				// Update session in store
				if updateErr := client.UpdateSession(sessionID.Value, newSession); updateErr != nil {
					log.Printf("[%s] Failed to update session after refresh: %v", requestID, updateErr)
					http.Error(w, "Failed to update session", http.StatusInternalServerError)
					return
				}

				log.Printf("[%s] Token refreshed, retrying CreatePost", requestID)

				// Retry CreatePost with new token
				if retryErr := client.CreatePost(r.Context(), newSession, text); retryErr != nil {
					http.Error(w, "Failed to create post: "+retryErr.Error(), http.StatusInternalServerError)
					return
				}
			} else {
				http.Error(w, "Failed to create post: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func createRecordHandler(client *bskyoauth.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

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
			// Refresh failed - redirect to login
			log.Printf("Token refresh failed, redirecting to login: %v", err)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		text := r.FormValue("text")
		if text == "" {
			http.Error(w, "Text is required", http.StatusBadRequest)
			return
		}

		// Validate text field (custom records can have larger limits)
		if err := bskyoauth.ValidateTextField(text, "text", 1000); err != nil {
			http.Error(w, fmt.Sprintf("Invalid text: %v", err), http.StatusBadRequest)
			return
		}

		// Create record using typed lexicon struct (demonstrates lexicon package usage)
		record := &lexicon.DemoRecord{
			LexiconTypeID: "com.demo.bskyoauth",
			Text:          text,
			CreatedAt:     time.Now().Format(time.RFC3339),
		}

		// Validate the record before creating
		if err := record.Validate(); err != nil {
			http.Error(w, fmt.Sprintf("Invalid record: %v", err), http.StatusBadRequest)
			return
		}

		// Convert to map for CreateRecord API
		recordMap := map[string]interface{}{
			"text":      record.Text,
			"createdAt": record.CreatedAt,
		}

		output, err := client.CreateRecord(r.Context(), session, "com.demo.bskyoauth", recordMap)
		if err != nil {
			// Check if error is due to expired token
			if strings.Contains(err.Error(), "invalid_token") && strings.Contains(err.Error(), "401") {
				log.Printf("Token expired during CreateRecord, attempting refresh for session: %s", sessionID.Value)

				// Attempt token refresh
				requestID := bskyoauth.GenerateRequestID()
				ctx := bskyoauth.WithRequestID(r.Context(), requestID)

				newSession, refreshErr := client.RefreshToken(ctx, session)
				if refreshErr != nil {
					log.Printf("[%s] Token refresh failed: %v", requestID, refreshErr)
					http.Error(w, "Session expired. Please log in again.", http.StatusUnauthorized)
					return
				}

				// Update session in store
				if updateErr := client.UpdateSession(sessionID.Value, newSession); updateErr != nil {
					log.Printf("[%s] Failed to update session after refresh: %v", requestID, updateErr)
					http.Error(w, "Failed to update session", http.StatusInternalServerError)
					return
				}

				log.Printf("[%s] Token refreshed, retrying CreateRecord", requestID)

				// Retry CreateRecord with new token
				output, err = client.CreateRecord(r.Context(), newSession, "com.demo.bskyoauth", recordMap)
				if err != nil {
					http.Error(w, "Failed to create record: "+err.Error(), http.StatusInternalServerError)
					return
				}
			} else {
				http.Error(w, "Failed to create record: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		log.Printf("Created com.demo.bskyoauth record: %s", output.Uri)

		// Extract rkey from URI for display
		rkey := extractRkeyFromURI(output.Uri)

		// Render success page with record details
		renderRecordCreatedPage(w, output.Uri, rkey)
	}
}

func deleteRecordHandler(client *bskyoauth.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

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
			// Refresh failed - redirect to login
			log.Printf("Token refresh failed, redirecting to login: %v", err)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		rkey := r.FormValue("rkey")
		if rkey == "" {
			http.Error(w, "Record key (rkey) is required", http.StatusBadRequest)
			return
		}

		err = client.DeleteRecord(r.Context(), session, "com.demo.bskyoauth", rkey)
		if err != nil {
			// Check if error is due to expired token
			if strings.Contains(err.Error(), "invalid_token") && strings.Contains(err.Error(), "401") {
				log.Printf("Token expired during DeleteRecord, attempting refresh for session: %s", sessionID.Value)

				// Attempt token refresh
				requestID := bskyoauth.GenerateRequestID()
				ctx := bskyoauth.WithRequestID(r.Context(), requestID)

				newSession, refreshErr := client.RefreshToken(ctx, session)
				if refreshErr != nil {
					log.Printf("[%s] Token refresh failed: %v", requestID, refreshErr)
					http.Error(w, "Session expired. Please log in again.", http.StatusUnauthorized)
					return
				}

				// Update session in store
				if updateErr := client.UpdateSession(sessionID.Value, newSession); updateErr != nil {
					log.Printf("[%s] Failed to update session after refresh: %v", requestID, updateErr)
					http.Error(w, "Failed to update session", http.StatusInternalServerError)
					return
				}

				log.Printf("[%s] Token refreshed, retrying DeleteRecord", requestID)

				// Retry DeleteRecord with new token
				if retryErr := client.DeleteRecord(r.Context(), newSession, "com.demo.bskyoauth", rkey); retryErr != nil {
					http.Error(w, "Failed to delete record: "+retryErr.Error(), http.StatusInternalServerError)
					return
				}
			} else {
				http.Error(w, "Failed to delete record: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		log.Printf("Deleted com.demo.bskyoauth record with rkey: %s", rkey)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func getRecordHandler(client *bskyoauth.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

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

		rkey := r.URL.Query().Get("rkey")
		if rkey == "" {
			http.Error(w, "Record key (rkey) is required", http.StatusBadRequest)
			return
		}

		record, err := client.GetRecord(r.Context(), session, "com.demo.bskyoauth", rkey)
		if err != nil {
			// Check if error is due to expired token
			if strings.Contains(err.Error(), "invalid_token") && strings.Contains(err.Error(), "401") {
				log.Printf("Token expired during GetRecord, attempting refresh for session: %s", sessionID.Value)

				requestID := bskyoauth.GenerateRequestID()
				ctx := bskyoauth.WithRequestID(r.Context(), requestID)

				newSession, refreshErr := client.RefreshToken(ctx, session)
				if refreshErr != nil {
					log.Printf("[%s] Token refresh failed: %v", requestID, refreshErr)
					http.Error(w, "Session expired. Please log in again.", http.StatusUnauthorized)
					return
				}

				if updateErr := client.UpdateSession(sessionID.Value, newSession); updateErr != nil {
					log.Printf("[%s] Failed to update session after refresh: %v", requestID, updateErr)
					http.Error(w, "Failed to update session", http.StatusInternalServerError)
					return
				}

				log.Printf("[%s] Token refreshed, retrying GetRecord", requestID)

				record, err = client.GetRecord(r.Context(), newSession, "com.demo.bskyoauth", rkey)
				if err != nil {
					http.Error(w, "Failed to get record: "+err.Error(), http.StatusInternalServerError)
					return
				}
			} else {
				http.Error(w, "Failed to get record: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		log.Printf("Retrieved com.demo.bskyoauth record: %s", rkey)

		// Return record as JSON
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(record)
	}
}

func putRecordHandler(client *bskyoauth.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

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

		rkey := r.FormValue("rkey")
		if rkey == "" {
			http.Error(w, "Record key (rkey) is required", http.StatusBadRequest)
			return
		}

		text := r.FormValue("text")
		if text == "" {
			http.Error(w, "Text is required", http.StatusBadRequest)
			return
		}

		// Validate text field
		if err := bskyoauth.ValidateTextField(text, "text", 1000); err != nil {
			http.Error(w, fmt.Sprintf("Invalid text: %v", err), http.StatusBadRequest)
			return
		}

		// Create record map
		recordMap := map[string]interface{}{
			"text":      text,
			"createdAt": time.Now().Format(time.RFC3339),
		}

		output, err := client.PutRecord(r.Context(), session, "com.demo.bskyoauth", rkey, recordMap)
		if err != nil {
			// Check if error is due to expired token
			if strings.Contains(err.Error(), "invalid_token") && strings.Contains(err.Error(), "401") {
				log.Printf("Token expired during PutRecord, attempting refresh for session: %s", sessionID.Value)

				requestID := bskyoauth.GenerateRequestID()
				ctx := bskyoauth.WithRequestID(r.Context(), requestID)

				newSession, refreshErr := client.RefreshToken(ctx, session)
				if refreshErr != nil {
					log.Printf("[%s] Token refresh failed: %v", requestID, refreshErr)
					http.Error(w, "Session expired. Please log in again.", http.StatusUnauthorized)
					return
				}

				if updateErr := client.UpdateSession(sessionID.Value, newSession); updateErr != nil {
					log.Printf("[%s] Failed to update session after refresh: %v", requestID, updateErr)
					http.Error(w, "Failed to update session", http.StatusInternalServerError)
					return
				}

				log.Printf("[%s] Token refreshed, retrying PutRecord", requestID)

				output, err = client.PutRecord(r.Context(), newSession, "com.demo.bskyoauth", rkey, recordMap)
				if err != nil {
					http.Error(w, "Failed to put record: "+err.Error(), http.StatusInternalServerError)
					return
				}
			} else {
				http.Error(w, "Failed to put record: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		log.Printf("Put com.demo.bskyoauth record: %s", output.Uri)

		// Render success page
		renderRecordCreatedPage(w, output.Uri, rkey)
	}
}

func listRecordsHandler(client *bskyoauth.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

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

		// Parse optional query params
		cursor := r.URL.Query().Get("cursor")
		limitStr := r.URL.Query().Get("limit")
		limit := 50 // default
		if limitStr != "" {
			if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 100 {
				limit = parsed
			}
		}

		opts := &bskyoauth.ListRecordsOptions{
			Limit:  limit,
			Cursor: cursor,
		}

		result, err := client.ListRecords(r.Context(), session, "com.demo.bskyoauth", opts)
		if err != nil {
			// Check if error is due to expired token
			if strings.Contains(err.Error(), "invalid_token") && strings.Contains(err.Error(), "401") {
				log.Printf("Token expired during ListRecords, attempting refresh for session: %s", sessionID.Value)

				requestID := bskyoauth.GenerateRequestID()
				ctx := bskyoauth.WithRequestID(r.Context(), requestID)

				newSession, refreshErr := client.RefreshToken(ctx, session)
				if refreshErr != nil {
					log.Printf("[%s] Token refresh failed: %v", requestID, refreshErr)
					http.Error(w, "Session expired. Please log in again.", http.StatusUnauthorized)
					return
				}

				if updateErr := client.UpdateSession(sessionID.Value, newSession); updateErr != nil {
					log.Printf("[%s] Failed to update session after refresh: %v", requestID, updateErr)
					http.Error(w, "Failed to update session", http.StatusInternalServerError)
					return
				}

				log.Printf("[%s] Token refreshed, retrying ListRecords", requestID)

				result, err = client.ListRecords(r.Context(), newSession, "com.demo.bskyoauth", opts)
				if err != nil {
					http.Error(w, "Failed to list records: "+err.Error(), http.StatusInternalServerError)
					return
				}
			} else {
				http.Error(w, "Failed to list records: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}

		log.Printf("Listed %d com.demo.bskyoauth records", len(result.Records))

		// Check Accept header - return JSON or HTML
		accept := r.Header.Get("Accept")
		if strings.Contains(accept, "application/json") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(result)
			return
		}

		// Render HTML page
		renderListRecordsPage(w, result)
	}
}

// renderListRecordsPage displays a list of records
func renderListRecordsPage(w http.ResponseWriter, result *bskyoauth.ListRecordsResult) {
	html := `<!DOCTYPE html>
<html>
<head>
	<title>Records - Bluesky OAuth Demo</title>
	<style>
		body { font-family: Arial, sans-serif; max-width: 900px; margin: 50px auto; padding: 20px; }
		h1 { color: #333; }
		.record {
			background: #f5f5f5;
			padding: 15px;
			margin: 10px 0;
			border-radius: 5px;
			border-left: 4px solid #0066cc;
		}
		.record-uri {
			font-family: monospace;
			font-size: 0.85em;
			color: #666;
			word-break: break-all;
		}
		.record-text {
			margin: 10px 0;
			font-size: 1.1em;
		}
		.record-actions {
			margin-top: 10px;
		}
		.record-actions a, .record-actions button {
			margin-right: 10px;
			padding: 5px 10px;
			text-decoration: none;
			background: #0066cc;
			color: white;
			border: none;
			border-radius: 3px;
			cursor: pointer;
			font-size: 12px;
		}
		.record-actions a:hover, .record-actions button:hover {
			background: #0052a3;
		}
		.record-actions form { display: inline; }
		.pagination {
			margin: 20px 0;
			padding: 10px;
			background: #eee;
			border-radius: 5px;
		}
		.pagination a {
			padding: 8px 15px;
			background: #0066cc;
			color: white;
			text-decoration: none;
			border-radius: 3px;
		}
		.empty-state {
			text-align: center;
			padding: 40px;
			color: #666;
		}
		.count { color: #666; margin-bottom: 20px; }
	</style>
</head>
<body>
	<h1>com.demo.bskyoauth Records</h1>
	<p class="count">Found ` + fmt.Sprintf("%d", len(result.Records)) + ` record(s)</p>`

	if len(result.Records) == 0 {
		html += `<div class="empty-state">
			<p>No records found in this collection.</p>
			<p><a href="/">Create your first record</a></p>
		</div>`
	} else {
		for _, rec := range result.Records {
			rkey := extractRkeyFromURI(rec.URI)
			text := ""
			if valueMap, ok := rec.Value.(map[string]interface{}); ok {
				if t, ok := valueMap["text"].(string); ok {
					text = t
				}
			}

			html += `<div class="record">
				<div class="record-uri">` + rec.URI + `</div>
				<div class="record-text">` + text + `</div>
				<div class="record-actions">
					<a href="/get-record?rkey=` + rkey + `">View JSON</a>
					<form action="/delete-record" method="post">
						<input type="hidden" name="rkey" value="` + rkey + `">
						<button type="submit" onclick="return confirm('Delete this record?')">Delete</button>
					</form>
				</div>
			</div>`
		}
	}

	if result.Cursor != "" {
		html += `<div class="pagination">
			<a href="/list-records?cursor=` + result.Cursor + `">Load More</a>
		</div>`
	}

	html += `
	<hr>
	<p><a href="/">← Back to Home</a></p>
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

		// Determine if we're running in secure mode (HTTPS)
		baseURL := os.Getenv("BASE_URL")
		if baseURL == "" {
			baseURL = "http://localhost:8181"
		}
		isSecure := strings.HasPrefix(baseURL, "https://")

		// Clear session cookie with matching security settings
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   isSecure,             // Must match original cookie
			SameSite: http.SameSiteLaxMode, // Must match original cookie
		})

		http.Redirect(w, r, "/", http.StatusFound)
	}
}
