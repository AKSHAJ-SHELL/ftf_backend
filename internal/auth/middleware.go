package auth

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/fundthefuture/ftf-backend/internal/apperr"
	"github.com/fundthefuture/ftf-backend/internal/db"
	"github.com/fundthefuture/ftf-backend/internal/db/dbq"
	"github.com/fundthefuture/ftf-backend/internal/httpx"
)

type ctxKey string

const claimsCtxKey ctxKey = "auth.claims"

// adminCacheTTL is the default lifetime of a positive admin-status cache hit.
// Short enough that a revoked admin loses access promptly, long enough to take
// the 4-round-trip RLS query off the hot path for most admin actions.
const adminCacheTTL = 60 * time.Second

// adminCacheEntry stores a cached IsAdmin result.
type adminCacheEntry struct {
	isAdmin bool
	expires time.Time
}

// Middleware wires JWT verification with the user pool so admin re-checks
// happen against the source-of-truth table via RLS-aware queries.
type Middleware struct {
	v        *Verifier
	userPool *db.UserPool
	logger   *slog.Logger

	adminCacheMu sync.Mutex
	adminCache   map[string]adminCacheEntry
}

func NewMiddleware(v *Verifier, p *db.UserPool, logger *slog.Logger) *Middleware {
	return &Middleware{
		v:          v,
		userPool:   p,
		logger:     logger,
		adminCache: make(map[string]adminCacheEntry),
	}
}

// RequireUser rejects requests without a valid Supabase JWT.
func (m *Middleware) RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := m.extract(r)
		if err != nil || c == nil {
			httpx.WriteError(w, r, apperr.Unauthorized("authentication required"))
			return
		}
		next.ServeHTTP(w, r.WithContext(withClaims(r.Context(), c)))
	})
}

// OptionalUser attaches claims when a token is present, but does not reject.
func (m *Middleware) OptionalUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if c, err := m.extract(r); err == nil && c != nil {
			ctx = withClaims(ctx, c)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin enforces a valid JWT AND a row in public.admins matched by sub.
// The admins check goes through the user pool so the admins RLS self-select
// policy is the actual gate. Result is cached per `sub` for adminCacheTTL to
// keep amplification under control.
func (m *Middleware) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := m.extract(r)
		if err != nil || c == nil {
			httpx.WriteError(w, r, apperr.Unauthorized("authentication required"))
			return
		}
		uuid, err := parseUUID(c.Sub)
		if err != nil {
			httpx.WriteError(w, r, apperr.Unauthorized("bad subject"))
			return
		}
		isAdmin, err := m.isAdmin(r.Context(), c, uuid)
		if err != nil {
			m.logger.Error("admin check failed", "err", err)
			httpx.WriteError(w, r, apperr.Internal("admin check failed"))
			return
		}
		if !isAdmin {
			httpx.WriteError(w, r, apperr.Forbidden("admin required"))
			return
		}
		next.ServeHTTP(w, r.WithContext(withClaims(r.Context(), c)))
	})
}

func (m *Middleware) isAdmin(ctx context.Context, c *Claims, uuid pgtype.UUID) (bool, error) {
	if hit, ok := m.cacheGet(c.Sub); ok {
		return hit, nil
	}
	var isAdmin bool
	err := m.userPool.WithUser(ctx, db.JWTContext{
		Sub:   c.Sub,
		Email: c.Email,
		Role:  "authenticated",
	}, func(q *dbq.Queries) error {
		ok, qerr := q.IsAdmin(ctx, uuid)
		if qerr != nil {
			return qerr
		}
		isAdmin = ok
		return nil
	})
	if err != nil {
		return false, err
	}
	m.cachePut(c.Sub, isAdmin)
	return isAdmin, nil
}

func (m *Middleware) cacheGet(sub string) (bool, bool) {
	m.adminCacheMu.Lock()
	defer m.adminCacheMu.Unlock()
	e, ok := m.adminCache[sub]
	if !ok || time.Now().After(e.expires) {
		if ok {
			delete(m.adminCache, sub)
		}
		return false, false
	}
	return e.isAdmin, true
}

func (m *Middleware) cachePut(sub string, isAdmin bool) {
	m.adminCacheMu.Lock()
	defer m.adminCacheMu.Unlock()
	// Bound the cache so a flood of garbage subs cannot grow it without limit.
	if len(m.adminCache) >= 1024 {
		for k := range m.adminCache {
			delete(m.adminCache, k)
			if len(m.adminCache) <= 512 {
				break
			}
		}
	}
	m.adminCache[sub] = adminCacheEntry{
		isAdmin: isAdmin,
		expires: time.Now().Add(adminCacheTTL),
	}
}

func (m *Middleware) extract(r *http.Request) (*Claims, error) {
	raw := BearerFromHeader(r.Header.Get("Authorization"))
	if raw == "" {
		return nil, nil
	}
	return m.v.Verify(r.Context(), raw)
}

// WithClaims is exported so tests and adjacent packages can inject identities.
func WithClaims(ctx context.Context, c *Claims) context.Context { return withClaims(ctx, c) }

// FromContext returns the Claims attached by middleware, or nil.
func FromContext(ctx context.Context) *Claims {
	if v, ok := ctx.Value(claimsCtxKey).(*Claims); ok {
		return v
	}
	return nil
}

func withClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsCtxKey, c)
}

func parseUUID(s string) (pgtype.UUID, error) {
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		return u, err
	}
	return u, nil
}
