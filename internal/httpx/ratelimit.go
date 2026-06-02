package httpx

import (
	"net/http"
	"time"

	"github.com/go-chi/httprate"
)

// RateLimit returns a per-IP rate limiter scoped to the given window.
// On limit hit, returns a structured 429 envelope.
//
// The key is derived from ClientIP, which uses the TCP peer (RemoteAddr) by
// default and honors X-Forwarded-For ONLY when the peer is a configured
// trusted proxy. This closes the bypass-by-spoofed-header weakness in
// httprate.KeyByRealIP.
func RateLimit(reqPerWindow int, window time.Duration) func(http.Handler) http.Handler {
	if reqPerWindow <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	return httprate.Limit(
		reqPerWindow,
		window,
		httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
			return ClientIP(r), nil
		}),
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "60")
			WriteJSON(w, http.StatusTooManyRequests, map[string]any{
				"code":    "rate_limited",
				"message": "too many requests",
			})
		}),
	)
}
