package httpx

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// NewLogger constructs the standard JSON slog logger. Use this for both
// HTTP middleware and worker code so format stays consistent.
func NewLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}

// emailHashKey is set once at startup via InitEmailHash. We use atomic.Value so
// any code path that calls HashEmail before init panics loudly rather than
// silently emitting unkeyed hashes.
var emailHashKey atomic.Pointer[[]byte]

// trustedProxies is set once at startup via InitTrustedProxies. Empty slice
// (the default) means do not trust X-Forwarded-For at all.
var trustedProxies atomic.Pointer[[]*net.IPNet]

// InitEmailHash installs the HMAC key used by HashEmail. MUST be called once
// at startup. The key is copied so the caller can zero out its source.
func InitEmailHash(key []byte) {
	cp := make([]byte, len(key))
	copy(cp, key)
	emailHashKey.Store(&cp)
}

// InitTrustedProxies installs the set of trusted proxy CIDRs. If nil or empty,
// X-Forwarded-For is never trusted and the real TCP peer (RemoteAddr) is used
// for both rate limiting and access logs.
func InitTrustedProxies(cidrs []*net.IPNet) {
	cp := append([]*net.IPNet(nil), cidrs...)
	trustedProxies.Store(&cp)
}

// Logging emits one structured access line per request. It never logs request
// bodies and never logs raw tokens.
func Logging(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			logger.LogAttrs(r.Context(), slog.LevelInfo, "http_request",
				slog.String("request_id", RequestIDFromContext(r.Context())),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", sw.status),
				slog.Int("bytes", sw.bytes),
				slog.Int64("dur_ms", time.Since(start).Milliseconds()),
				slog.String("remote", ClientIP(r)),
			)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
	wrote  bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// ClientIP returns the request's real client IP. Walks X-Forwarded-For from
// right to left, skipping addresses that are inside a configured trusted-proxy
// CIDR. If the TCP peer (RemoteAddr) itself is not a trusted proxy, no XFF
// hops are honored and RemoteAddr wins. Empty trusted set = always RemoteAddr.
func ClientIP(r *http.Request) string {
	peerHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peerHost = r.RemoteAddr
	}
	peer := net.ParseIP(peerHost)

	tpPtr := trustedProxies.Load()
	if tpPtr == nil || len(*tpPtr) == 0 || peer == nil || !ipInCIDRs(peer, *tpPtr) {
		return peerHost
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peerHost
	}
	hops := strings.Split(xff, ",")
	// Walk right→left; the first hop that is NOT a trusted proxy is the client.
	for i := len(hops) - 1; i >= 0; i-- {
		h := strings.TrimSpace(hops[i])
		ip := net.ParseIP(h)
		if ip == nil {
			continue
		}
		if !ipInCIDRs(ip, *tpPtr) {
			return ip.String()
		}
	}
	// All hops trusted: fall back to the leftmost non-empty value (best guess).
	for _, h := range hops {
		if t := strings.TrimSpace(h); t != "" {
			return t
		}
	}
	return peerHost
}

func ipInCIDRs(ip net.IP, cidrs []*net.IPNet) bool {
	for _, c := range cidrs {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}

// HashEmail returns a hex HMAC-SHA-256 of a normalized email keyed by the
// process-wide email-hash key. Bare SHA-256 of an email is rainbow-tableable
// in seconds; HMAC with a server-side key is not.
func HashEmail(email string) string {
	keyPtr := emailHashKey.Load()
	if keyPtr == nil {
		panic("httpx: HashEmail called before InitEmailHash")
	}
	mac := hmac.New(sha256.New, *keyPtr)
	mac.Write([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(mac.Sum(nil))
}

// HashEmailBytes is the raw-byte form used by callers that store the hash
// directly in a bytea column. Same HMAC, same key.
func HashEmailBytes(email string) []byte {
	keyPtr := emailHashKey.Load()
	if keyPtr == nil {
		panic("httpx: HashEmailBytes called before InitEmailHash")
	}
	mac := hmac.New(sha256.New, *keyPtr)
	mac.Write([]byte(strings.ToLower(strings.TrimSpace(email))))
	return mac.Sum(nil)
}
