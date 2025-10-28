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

	// Security check: warn if not using HTTPS in non-local environments
	if !strings.HasPrefix(baseURL, "https://") && !strings.Contains(baseURL, "localhost") && !strings.Contains(baseURL, "127.0.0.1") {
		log.Println("⚠️  WARNING: BASE_URL is not using HTTPS!")
		log.Println("⚠️  OAuth flows over HTTP expose credentials to interception.")
		log.Println("⚠️  HTTPS is REQUIRED for production deployments.")
		log.Println("⚠️  See README.md Security section for deployment guidance.")
	}

	// Create OAuth client
	client := bskyoauth.NewClient(baseURL)

	// Set up HTTP handlers
	http.HandleFunc("/", homeHandler(client))
	http.HandleFunc("/client-metadata.json", client.ClientMetadataHandler())
	http.HandleFunc("/login", loginHandler(client))
	http.HandleFunc("/callback", client.CallbackHandler(callbackSuccessHandler))
	http.HandleFunc("/post", postHandler(client))
	http.HandleFunc("/create-ongaku", createOngakuHandler(client))
	http.HandleFunc("/delete-ongaku", deleteOngakuHandler(client))
	http.HandleFunc("/logout", logoutHandler(client))

	log.Println("Server starting on :8181")
	log.Println("Base URL:", baseURL)
	if strings.HasPrefix(baseURL, "https://") {
		log.Println("✓ Using HTTPS - secure configuration")
	}
	log.Fatal(http.ListenAndServe(":8181", nil))
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
	<h2>club.ongaku.prototype</h2>
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
		handle := r.URL.Query().Get("handle")
		if handle == "" {
			http.Error(w, "handle parameter required", http.StatusBadRequest)
			return
		}

		log.Printf("Starting auth flow for handle: %s", handle)

		flowState, err := client.StartAuthFlow(r.Context(), handle)
		if err != nil {
			log.Printf("Failed to start auth flow: %v", err)
			http.Error(w, "Failed to start auth flow: "+err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("Redirecting to: %s", flowState.AuthURL)
		http.Redirect(w, r, flowState.AuthURL, http.StatusFound)
	}
}

func callbackSuccessHandler(w http.ResponseWriter, r *http.Request, sessionID string) {
	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
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

		record := map[string]interface{}{
			"text":      text,
			"createdAt": time.Now().Format(time.RFC3339),
		}

		output, err := client.CreateRecord(r.Context(), session, "club.ongaku.prototype", record)
		if err != nil {
			http.Error(w, "Failed to create record: "+err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("Created club.ongaku.prototype record: %s", output.Uri)
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

		err = client.DeleteRecord(r.Context(), session, "club.ongaku.prototype", rkey)
		if err != nil {
			http.Error(w, "Failed to delete record: "+err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("Deleted club.ongaku.prototype record with rkey: %s", rkey)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func logoutHandler(client *bskyoauth.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID, err := r.Cookie("session_id")
		if err == nil {
			client.DeleteSession(sessionID.Value)
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})

		http.Redirect(w, r, "/", http.StatusFound)
	}
}
