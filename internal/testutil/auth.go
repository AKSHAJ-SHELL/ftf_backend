//go:build integration

package testutil

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AsRole runs fn inside a transaction with SET LOCAL ROLE = role and the
// supplied JWT claims so RLS policies see the correct identity.
func AsRole(t *testing.T, pool *pgxpool.Pool, role string, claims map[string]any, fn func(pgx.Tx) error) error {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL ROLE %s", role)); err != nil {
		return err
	}
	if claims == nil {
		claims = map[string]any{}
	}
	js, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('request.jwt.claims', $1, true)", string(js)); err != nil {
		return err
	}
	return fn(tx)
}
