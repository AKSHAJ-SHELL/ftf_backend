package httpx

import (
	"net/http"
	"strings"
)

// CORS applies a strict allowlist. The wildcard origin is intentionally
// unsupported — config layer also rejects "*". Preflight is handled here so
// downstream handlers never see OPTIONS.
func CORS(allowed []string) func(http.Handler) http.Handler {
	allow := make(map[string]struct{}, len(allowed))
	for _, o := range allowed {
		allow[strings.ToLower(strings.TrimRight(o, "/"))] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := strings.ToLower(strings.TrimRight(r.Header.Get("Origin"), "/"))
			if origin != "" {
				if _, ok := allow[origin]; ok {
					w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
					w.Header().Set("Vary", "Origin")
					// No Access-Control-Allow-Credentials: we authenticate via
					// Authorization bearer tokens, not cookies. Disallowing
					// credentialed requests blocks a class of cookie-based CSRF.
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-Id")
					w.Header().Set("Access-Control-Max-Age", "600")
				}
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
