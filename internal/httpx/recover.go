package httpx

import (
	"log/slog"
	"net/http"
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/fundthefuture/ftf-backend/internal/apperr"
)

// Recover catches panics from downstream handlers, logs them with the request
// id and a redacted stack, and returns a generic 500. The client never sees
// internal details.
func Recover(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error("panic recovered",
						"request_id", RequestIDFromContext(r.Context()),
						"path", r.URL.Path,
						"method", r.Method,
						"panic", rec,
						"stack", redactStack(debug.Stack()),
					)
					WriteError(w, r, apperr.Internal("internal"))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// argsRe captures the argument list of a stack frame's function call so we can
// replace it with a placeholder. Stack frames look like:
//
//	package.func(0x1234, "secret-email", ...)
//
// where the arg values can leak struct contents, byte slices interpreted as
// strings, and similar PII. Stripping the parenthesized tail neuters this
// while preserving the function name and call structure.
var argsRe = regexp.MustCompile(`(?m)^([^\s\t][^(]*)\(.*\)$`)

// offsetRe strips the `+0xNN` PC offset suffix on file:line entries. The
// offset is rarely useful for triage and can identify build-specific layouts.
var offsetRe = regexp.MustCompile(` \+0x[0-9a-fA-F]+$`)

// redactStack scrubs a debug.Stack() output:
//   - function-arg tuples are replaced with "(...)"
//   - PC offsets are stripped
//   - the goroutine header line is kept (just the goroutine id)
//
// The output is enough to map a panic to source lines without leaking secrets
// that happened to be on the stack at the moment of the panic.
func redactStack(raw []byte) string {
	lines := strings.Split(string(raw), "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = argsRe.ReplaceAllString(l, `$1(...)`)
		l = offsetRe.ReplaceAllString(l, "")
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}
