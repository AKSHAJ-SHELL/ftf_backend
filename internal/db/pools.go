// Package db owns the only references to pgxpool.Pool in the codebase.
// All other packages talk to one of the two distinct wrapper types below so
// the compiler enforces the rule "user handlers never touch service-role".
package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/fundthefuture/ftf-backend/internal/db/dbq"
)

// UserPool is the RLS-enforced pool. Handlers receive this. Per-request
// transactions SET LOCAL ROLE and inject JWT claims so Supabase RLS policies
// evaluate against the caller's identity.
type UserPool struct{ p *pgxpool.Pool }

// ServicePool wraps a pool connected with the Supabase service-role connection
// string (BYPASSRLS). It is the only way to perform privileged writes
// (notification status updates, post-token state transitions). Its type does
// not satisfy any common interface with UserPool by design.
type ServicePool struct{ p *pgxpool.Pool }

// PoolOpts configures both pool constructors. MaxConns must be >= 1.
type PoolOpts struct {
	MaxConns int32
}

func defaults(opts PoolOpts) PoolOpts {
	if opts.MaxConns < 1 {
		opts.MaxConns = 10
	}
	return opts
}

// NewUserPool opens the user-context pool.
func NewUserPool(ctx context.Context, dsn string, opts PoolOpts) (*UserPool, error) {
	if dsn == "" {
		return nil, errors.New("user pool dsn is empty")
	}
	opts = defaults(opts)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse user dsn: %w", err)
	}
	cfg.MaxConns = opts.MaxConns
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect user pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping user pool: %w", err)
	}
	return &UserPool{p: pool}, nil
}

// NewServicePool opens the service-role pool.
func NewServicePool(ctx context.Context, dsn string, opts PoolOpts) (*ServicePool, error) {
	if dsn == "" {
		return nil, errors.New("service pool dsn is empty")
	}
	opts = defaults(opts)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse service dsn: %w", err)
	}
	cfg.MaxConns = opts.MaxConns
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect service pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping service pool: %w", err)
	}
	return &ServicePool{p: pool}, nil
}

func (u *UserPool) Close()    { u.p.Close() }
func (s *ServicePool) Close() { s.p.Close() }

// Pool exposes the underlying pgxpool for liveness checks only. Keep usage
// minimal — query helpers belong on dbq.Queries.
func (u *UserPool) Pool() *pgxpool.Pool { return u.p }

// Pool exposes the service-role pool for liveness checks only.
func (s *ServicePool) Pool() *pgxpool.Pool { return s.p }

// JWTContext carries the minimum identity needed for RLS policies.
// Zero value (Role == "") means anon.
type JWTContext struct {
	Sub   string
	Email string
	Role  string // "authenticated" or "anon"
}

// validRoles enumerates the only db role names this code path will SET LOCAL
// to. Anything outside this set is rejected so the role name can be safely
// concatenated into the SET LOCAL statement (which is the one place a role
// cannot be parameterized).
var validRoles = map[string]struct{}{
	"anon":          {},
	"authenticated": {},
}

// WithUser opens a transaction on the user pool with SET LOCAL ROLE and the
// JWT claims injected so RLS policies see the right identity. The fn is run
// inside the transaction; commit happens iff fn returns nil.
func (u *UserPool) WithUser(ctx context.Context, jc JWTContext, fn func(*dbq.Queries) error) error {
	role := jc.Role
	if role == "" {
		role = "anon"
	}
	if _, ok := validRoles[role]; !ok {
		return fmt.Errorf("invalid db role %q", role)
	}
	tx, err := u.p.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Role identifiers cannot be parameterized; use pgx's identifier sanitizer
	// to quote and escape defensively even though the value is whitelisted.
	roleIdent := pgx.Identifier{role}.Sanitize()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+roleIdent); err != nil {
		return err
	}

	claims := map[string]any{
		"role": role,
	}
	if jc.Sub != "" {
		claims["sub"] = jc.Sub
	}
	if jc.Email != "" {
		claims["email"] = jc.Email
	}
	js, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('request.jwt.claims', $1, true)", string(js)); err != nil {
		return err
	}

	q := dbq.New(tx)
	if err := fn(q); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Queries returns a service-role *dbq.Queries directly. RLS does not apply
// because the role bypasses it; callers MUST treat the returned queries as
// privileged. Wired only into the notification worker and the narrow
// token-gated state transitions in the subscribers service.
func (s *ServicePool) Queries() *dbq.Queries { return dbq.New(s.p) }

// WithTx runs fn in a service-role transaction.
func (s *ServicePool) WithTx(ctx context.Context, fn func(*dbq.Queries) error) error {
	tx, err := s.p.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(dbq.New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
