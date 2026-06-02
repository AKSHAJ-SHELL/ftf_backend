//go:build integration

package testutil

import (
	"context"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

//go:embed auth_shim.sql grants.sql
var assets embed.FS

// MigrationsDir returns the absolute path to the production migrations directory.
// Tests run with a working directory of the package under test, so we walk up.
func MigrationsDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		candidate := filepath.Join(dir, "migrations")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
	}
	t.Fatal("could not find migrations/ directory")
	return ""
}

// StartPostgres spins up a Postgres container, applies the auth shim, all
// production migrations (in lexical order), and grants. Returns a service-role
// pool plus a constructor for per-role pools.
func StartPostgres(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("ftf_test"),
		tcpostgres.WithUsername("ftf"),
		tcpostgres.WithPassword("ftf"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	t.Cleanup(func() {
		_ = container.Terminate(context.Background())
	})

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("dsn: %v", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := applySQL(ctx, pool, mustEmbed("auth_shim.sql")); err != nil {
		t.Fatalf("auth shim: %v", err)
	}

	dir := MigrationsDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir migrations: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		stripped := stripGooseDown(string(body))
		if err := applySQL(ctx, pool, stripped); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}

	if err := applySQL(ctx, pool, mustEmbed("grants.sql")); err != nil {
		t.Fatalf("grants: %v", err)
	}
	return pool, dsn
}

func applySQL(ctx context.Context, pool *pgxpool.Pool, sql string) error {
	if strings.TrimSpace(sql) == "" {
		return nil
	}
	_, err := pool.Exec(ctx, sql)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	return nil
}

// stripGooseDown removes the down-migration section so we can apply files
// directly via Exec without running goose.
func stripGooseDown(s string) string {
	idx := strings.Index(s, "-- +goose Down")
	if idx == -1 {
		return s
	}
	return s[:idx]
}

func mustEmbed(name string) string {
	b, err := assets.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return string(b)
}
