package bskyoauth

import (
	"net/http"

	internalhttp "github.com/shindakun/bskyoauth/internal/http"
)

// LoggingMiddleware returns middleware that logs HTTP requests and responses.
// It logs the HTTP method, path, status code, duration, and remote address.
//
// Usage:
//
//	mux := http.NewServeMux()
//	// ... set up handlers ...
//	handler := bskyoauth.LoggingMiddleware()(mux)
//	http.ListenAndServe(":8080", handler)
func LoggingMiddleware() func(http.Handler) http.Handler {
	loggerGetter := func(r *http.Request) internalhttp.Logger {
		return LoggerFromContext(r.Context())
	}
	return internalhttp.LoggingMiddleware(loggerGetter)
}
