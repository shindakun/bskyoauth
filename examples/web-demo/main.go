package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/shindakun/bskyoauth"
)

func main() {
	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8181"
	}

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
	// Login/callback: 5 requests per second, burst of 10 (prevent brute force)
	authLimiter := bskyoauth.NewRateLimiter(5, 10)
	authLimiter.StartCleanup(5*time.Minute, 10*time.Minute)

	// API operations: 10 requests per second, burst of 20 (normal usage)
	apiLimiter := bskyoauth.NewRateLimiter(10, 20)
	apiLimiter.StartCleanup(5*time.Minute, 10*time.Minute)

	// Set up HTTP handlers with rate limiting
	mux := http.NewServeMux()
	mux.HandleFunc("/", homeHandler(client))
	mux.HandleFunc("/client-metadata.json", client.ClientMetadataHandler())
	mux.HandleFunc("/login", authLimiter.Middleware(loginHandler(client)))
	mux.HandleFunc("/callback", authLimiter.Middleware(client.CallbackHandler(callbackSuccessHandler)))
	mux.HandleFunc("/post", apiLimiter.Middleware(postHandler(client)))
	mux.HandleFunc("/create-record", apiLimiter.Middleware(createRecordHandler(client)))
	mux.HandleFunc("/delete-record", apiLimiter.Middleware(deleteRecordHandler(client)))
	mux.HandleFunc("/logout", logoutHandler(client))

	// Apply security headers middleware
	handler := bskyoauth.SecurityHeadersMiddleware()(mux)

	log.Println("Server starting on :8181")
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
	log.Println("  - Auth endpoints: 5 req/s (burst: 10)")
	log.Println("  - API endpoints: 10 req/s (burst: 20)")
	log.Println("✓ Security headers enabled (auto-detects localhost)")
	log.Println("✓ HTTP timeouts configured:")
	log.Println("  - Client requests: 30s total timeout")
	log.Println("  - Server read: 15s, write: 15s, idle: 60s")

	// Configure HTTP server with timeouts to prevent resource exhaustion attacks
	server := &http.Server{
		Addr:         ":8181",
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
	<h2>com.demo.bskyoauth</h2>
	<form action="/create-record" method="post">
		<textarea name="text" rows="4" cols="50" placeholder="Custom record text..."></textarea><br>
		<button type="submit">Create Custom Record</button>
	</form>
	<br>
	<form action="/delete-record" method="post">
		<input type="text" name="rkey" placeholder="Record key (rkey)" required><br>
		<button type="submit">Delete Custom Record</button>
	</form>
	<br>
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

func loginHandler(client *bskyoauth.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Add request ID for correlation
		requestID := bskyoauth.GenerateRequestID()
		ctx := bskyoauth.WithRequestID(r.Context(), requestID)

		handle := r.URL.Query().Get("handle")
		if handle == "" {
			http.Error(w, "handle parameter required", http.StatusBadRequest)
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

func callbackSuccessHandler(w http.ResponseWriter, r *http.Request, sessionID string) {
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
		HttpOnly: true,                 // Prevents JavaScript access
		Secure:   isSecure,             // HTTPS only in production
		SameSite: http.SameSiteLaxMode, // CSRF protection
		MaxAge:   2592000,              // 30 days (configurable)
	})

	http.Redirect(w, r, "/", http.StatusFound)
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

		record := map[string]interface{}{
			"text":      text,
			"createdAt": time.Now().Format(time.RFC3339),
		}

		output, err := client.CreateRecord(r.Context(), session, "com.demo.bskyoauth", record)
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
				output, err = client.CreateRecord(r.Context(), newSession, "com.demo.bskyoauth", record)
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
		http.Redirect(w, r, "/", http.StatusFound)
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
