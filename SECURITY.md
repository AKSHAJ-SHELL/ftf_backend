# Security model — Fund the Future Go backend

This document explains the guarantees the backend enforces, the threat model it assumes, and the explicit non-goals.

## Defense in depth

The same property is enforced at multiple layers. If any one layer is misconfigured, the others still hold.

| Property | Enforced at |
| --- | --- |
| Subscribers may only be inserted in `pending` state | (1) Postgres table-level `CHECK` constraint, (2) RLS `WITH CHECK` on the insert policy, (3) the only public endpoint that writes calls `UpsertPendingSubscriber` which hardcodes `'pending'`. |
| Authenticated user reads only their own subscriber row | (1) RLS `USING` clause matches `lower(auth.jwt() ->> 'email')`, (2) handler queries via the user pool so RLS is the actual gate. |
| Admins gate all admin reads | (1) RLS policy `EXISTS (SELECT 1 FROM public.admins …)`, (2) chi middleware re-queries `public.admins` per request via the user pool, (3) `public.admins.SELECT` policy only lets you see your own row, so the lookup is itself RLS-scoped. |
| Service-role power is not reachable from HTTP handlers | (1) `*db.UserPool` and `*db.ServicePool` are distinct Go types with no shared interface, (2) CI grep gate forbids `db.ServicePool` references outside `internal/notifications`, `internal/subscribers`, `internal/admins/HandleResendConfirm` and `cmd/server`. |
| Confirm token cannot be replayed as unsubscribe | (1) `internal/tokens` HMAC payload includes a `purpose` byte, (2) verifier rejects mismatched purposes with no DB roundtrip. |
| No email enumeration via subscribe | (1) Uniform 202 response on success/invalid/already-exists, (2) constant-time delay floor in handler. |
| PII never logged | (1) `httpx.HashEmail` is the only sanctioned way to mention an email in logs, (2) raw tokens are never logged, (3) request bodies are never logged. |

## Component isolation

```
HTTP handlers ──► *db.UserPool ──► Postgres RLS enforces identity
                                          ▲
                                          │ (impossible by type)
                                          │
Worker + admin resend ──► *db.ServicePool ──► bypasses RLS (BYPASSRLS role)
```

Handlers literally cannot import / accept `*db.ServicePool` because:
- There is no constructor function in scope that gives handlers a `*db.ServicePool`.
- There is no interface that both pool types satisfy.
- The CI grep gate fails the build if `db.ServicePool` appears in `internal/{auth,httpx}` or in any new package not already listed in the allowlist.

## Token design

- Algorithm: HMAC-SHA256, key from `TOKEN_SIGNING_KEY` (validated `>= 32 bytes` at startup).
- Payload: `[version:1][purpose:1][issued_at:8][expires_at:8][subject]`. Constant-time verification.
- Encoding: URL-safe base64 (no padding).
- Lifetimes:
  - `confirm_subscriber`: 7 days.
  - `unsubscribe_subscriber`: unbounded — unsubscribe links must stay clickable forever per CAN-SPAM / RFC 8058.
- The token never appears in any log. The DB stores SHA-256 of the raw confirm token; the verifier compares constant-time.

## Network surface

- Strict CORS allowlist. `*` is rejected at config load.
- HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, minimal `Permissions-Policy`.
- Per-IP rate limits via `httprate`. Subscribe, confirm, and default have their own named buckets.
- Panic recovery: logs with request id, returns generic `500 {"code":"internal","message":"internal"}`. No stack traces leak.

## Things this backend does NOT do

- It does not accept payments. Stripe integration is intentionally out of scope.
- It does not host the marketing site or any web UI. The Next.js app in `../ftf-app/` is separate.
- It does not store passwords; all user identity is delegated to Supabase Auth.
- It does not send transactional email synchronously. All mail flows through the notification queue so a Resend outage cannot block an HTTP request.

## Reporting

Open a private issue or email `security@fundthefuture.org`. Please do not file public issues for vulnerabilities.
