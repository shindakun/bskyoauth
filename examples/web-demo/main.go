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

	// Create OAuth client
	client := bskyoauth.NewClient(baseURL)

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
	mux.HandleFunc("/create-ongaku", apiLimiter.Middleware(createOngakuHandler(client)))
	mux.HandleFunc("/delete-ongaku", apiLimiter.Middleware(deleteOngakuHandler(client)))
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
	log.Fatal(http.ListenAndServe(":8181", handler))
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
	<form action="/create-ongaku" method="post">
		<textarea name="text" rows="4" cols="50" placeholder="Ongaku prototype text..."></textarea><br>
		<button type="submit">Create Ongaku Record</button>
	</form>
	<br>
	<form action="/delete-ongaku" method="post">
		<input type="text" name="rkey" placeholder="Record key (rkey)" required><br>
		<button type="submit">Delete Ongaku Record</button>
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
		w.Write([]byte(html))
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
		HttpOnly: true,                  // Prevents JavaScript access
		Secure:   isSecure,               // HTTPS only in production
		SameSite: http.SameSiteLaxMode,   // CSRF protection
		MaxAge:   2592000,                // 30 days (configurable)
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

		if err := client.CreatePost(r.Context(), session, text); err != nil {
			http.Error(w, "Failed to create post: "+err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func createOngakuHandler(client *bskyoauth.Client) http.HandlerFunc {
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
			http.Error(w, "Failed to create record: "+err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("Created com.demo.bskyoauth record: %s", output.Uri)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func deleteOngakuHandler(client *bskyoauth.Client) http.HandlerFunc {
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

		rkey := r.FormValue("rkey")
		if rkey == "" {
			http.Error(w, "Record key (rkey) is required", http.StatusBadRequest)
			return
		}

		err = client.DeleteRecord(r.Context(), session, "com.demo.bskyoauth", rkey)
		if err != nil {
			http.Error(w, "Failed to delete record: "+err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("Deleted com.demo.bskyoauth record with rkey: %s", rkey)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func logoutHandler(client *bskyoauth.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID, err := r.Cookie("session_id")
		if err == nil {
			client.DeleteSession(sessionID.Value)
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
			Secure:   isSecure,               // Must match original cookie
			SameSite: http.SameSiteLaxMode,   // Must match original cookie
		})

		http.Redirect(w, r, "/", http.StatusFound)
	}
}
