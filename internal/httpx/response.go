package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fundthefuture/ftf-backend/internal/apperr"
)

// WriteJSON writes v as compact JSON. Status defaults to 200.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteHTML writes a small static HTML body. Used for the interstitial pages
// served on GET to /v1/subscribers/confirm and /v1/subscribers/unsubscribe.
func WriteHTML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// WriteError translates app errors into wire envelopes. It NEVER leaks
// internal cause details to the response body.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apperr.Error
	if !errors.As(err, &ae) {
		ae = apperr.Internal("internal")
	}
	WriteJSON(w, ae.Status, map[string]any{
		"code":       ae.Code,
		"message":    ae.Message,
		"request_id": RequestIDFromContext(r.Context()),
	})
}

// HealthOK is the liveness probe.
func HealthOK(w http.ResponseWriter, _ *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Readyz pings every supplied pool before reporting ready. Fail-fast on the
// first unhealthy pool. nil pools are skipped (so callers can pass a single
// pool by passing nil for the other).
func Readyz(pools ...*pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		for _, pool := range pools {
			if pool == nil {
				continue
			}
			if err := pool.Ping(ctx); err != nil {
				slog.Default().Warn("readyz ping failed", "err", err)
				WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "down"})
				return
			}
		}
		WriteJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}
