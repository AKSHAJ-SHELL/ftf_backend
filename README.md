# Fund the Future — Go Backend

Production-grade Go backend for Fund the Future. Owns:

- Subscriber list with **double opt-in** and **signed one-click unsubscribe**.
- Notification/email worker (Resend) with retry/backoff and an outbound rate limit.
- Supabase JWT-authenticated admin routes for observability and ops.

Out of scope: payments. Donations are handled offsite — this backend never sees Stripe.

## Stack

| Layer | Choice |
| --- | --- |
| HTTP | [chi](https://github.com/go-chi/chi), `httprate` |
| DB driver | [pgx v5](https://github.com/jackc/pgx) (dual pools) |
| Query gen | [sqlc](https://github.com/sqlc-dev/sqlc) |
| Migrations | [goose](https://github.com/pressly/goose) |
| Auth | [Supabase Auth](https://supabase.com/docs/guides/auth) JWTs (HS256 or JWKS) |
| Email | [Resend](https://resend.com) |
| Tokens | HMAC-SHA256, purpose-bound (`internal/tokens`) |
| Logging | `log/slog` (JSON, hashes email before logging) |

## Setup

```bash
brew install go sqlc goose          # one-time
cp .env.example .env                # fill in real values
go mod tidy
goose -dir migrations postgres "$DATABASE_URL" up
sqlc generate
go run ./cmd/server
```

`PORT` defaults to `8080`. `/healthz` is the liveness probe, `/readyz` pings the DB.

## Project layout

```
cmd/server/main.go         # entry point + wiring + graceful shutdown
internal/config/           # typed env loader, fail-fast validation
internal/db/               # dual pgx pools (UserPool + ServicePool, distinct types)
internal/db/dbq/           # sqlc-generated queries (DO NOT EDIT BY HAND)
internal/auth/             # Supabase JWT verifier + RequireUser/RequireAdmin
internal/httpx/            # request id, recover, CORS, security headers, logging, rate limit
internal/apperr/           # typed errors -> safe JSON envelopes
internal/tokens/           # HMAC-signed purpose-bound tokens
internal/email/            # Sender interface + Resend impl + in-memory fake
internal/notifications/    # enqueue + worker + retry/backoff
internal/subscribers/      # double-opt-in subscribe/confirm/unsubscribe
internal/admins/           # admin routes (gated by public.admins via RLS)
internal/testutil/         # auth shim + testcontainers Postgres helpers (integration tests)
migrations/                # goose SQL with RLS policies + inline COMMENT ON POLICY
queries/                   # sqlc input
docs/ENDPOINTS.md          # endpoint contract
```

## API contract

See `docs/ENDPOINTS.md`.

## Security

See `SECURITY.md` for the full threat model. Highlights:

- **Service-role pool is isolated to the worker.** Handlers receive `*db.UserPool` (RLS-enforced); the worker receives `*db.ServicePool`. The two types share no interface — the compiler forbids substitution.
- **RLS on every table** with `FORCE ROW LEVEL SECURITY`. Anon/authenticated can only do exactly what the policies allow.
- **No enumeration**: `POST /v1/subscribers` returns a uniform 202 whether the email exists, is fresh, or is invalid. Response timing is padded to a constant minimum.
- **Signed tokens are purpose-bound**: a confirm token cannot be replayed as an unsubscribe token (and vice versa).
- **PII in logs**: never. Emails are SHA-256 hashed before any log statement; tokens are never logged.

## Tests

```bash
go test ./...                          # unit tests
go test -tags=integration ./...        # RLS smoke + Postgres-backed (requires Docker)
```

Integration tests spin up a Postgres container, install a minimal `auth` schema shim, apply every production migration in order, then assert the RLS policies actually block the operations they should.

## Operational notes

- Admin provisioning happens by inserting a row in `public.admins`. There is no HTTP route for this on purpose; do it via SQL through the service-role connection (e.g. `INSERT INTO public.admins(user_id) VALUES('…');`).
- Outbound mail is rate-limited (`OUTBOUND_EMAIL_RPS`); set to your Resend plan's safe rate, not your absolute cap.
- The notification queue uses `FOR UPDATE SKIP LOCKED` + a `locked_until` lease; safe for N>1 worker processes against the same database.
