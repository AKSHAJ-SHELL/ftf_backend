//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fundthefuture/ftf-backend/internal/testutil"
)

func TestRLSBlocksAnonReads(t *testing.T) {
	pool, _ := testutil.StartPostgres(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `INSERT INTO public.subscribers (email, status) VALUES ('seed@example.org','confirmed')`); err == nil {
		_, _ = pool.Exec(ctx, `UPDATE public.subscribers SET confirmed_at = now() WHERE email = 'seed@example.org'`)
	}

	cases := []struct {
		name  string
		query string
	}{
		{"notifications", "SELECT * FROM public.notifications"},
		{"email_log", "SELECT * FROM public.email_log"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := testutil.AsRole(t, pool, "anon", nil, func(tx pgx.Tx) error {
				rows, err := tx.Query(context.Background(), tc.query)
				if err != nil {
					return err
				}
				defer rows.Close()
				if rows.Next() {
					return errors.New("anon should not see any rows")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSubscriberInsertRejectsConfirmedStatus(t *testing.T) {
	pool, _ := testutil.StartPostgres(t)
	err := testutil.AsRole(t, pool, "anon", nil, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(),
			`INSERT INTO public.subscribers (email, status, confirmed_at) VALUES ('bad@example.org','confirmed', now())`)
		return err
	})
	if err == nil {
		t.Fatal("expected RLS or CHECK to reject pre-confirmed insert")
	}
}

func TestSubscriberOwnerSelect(t *testing.T) {
	pool, _ := testutil.StartPostgres(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO public.subscribers (email, status) VALUES ('owner@example.org','pending')`); err != nil {
		t.Fatal(err)
	}
	uid := uuid.New().String()
	err := testutil.AsRole(t, pool, "authenticated", map[string]any{
		"sub":   uid,
		"email": "owner@example.org",
		"role":  "authenticated",
	}, func(tx pgx.Tx) error {
		var got string
		if err := tx.QueryRow(ctx, `SELECT email::text FROM public.subscribers`).Scan(&got); err != nil {
			return err
		}
		if got != "owner@example.org" {
			t.Fatalf("got %q", got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	err = testutil.AsRole(t, pool, "authenticated", map[string]any{
		"sub":   uuid.New().String(),
		"email": "someone-else@example.org",
		"role":  "authenticated",
	}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT email FROM public.subscribers`)
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			return errors.New("non-owner authenticated user must not see other subscribers")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAdminCanSeeAllSubscribers(t *testing.T) {
	pool, _ := testutil.StartPostgres(t)
	ctx := context.Background()
	adminID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO auth.users (id, email) VALUES ($1,$2)`, adminID, "admin@example.org"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO public.admins (user_id) VALUES ($1)`, adminID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO public.subscribers (email, status) VALUES ('a@example.org','pending'), ('b@example.org','pending')`); err != nil {
		t.Fatal(err)
	}
	err := testutil.AsRole(t, pool, "authenticated", map[string]any{
		"sub":   adminID.String(),
		"email": "admin@example.org",
		"role":  "authenticated",
	}, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.subscribers`).Scan(&n); err != nil {
			return err
		}
		if n < 2 {
			t.Fatalf("admin should see >=2 rows, got %d", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
