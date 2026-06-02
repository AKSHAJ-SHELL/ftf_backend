# API endpoints

All non-`/healthz`, non-`/readyz` routes live under `/v1`.

All responses are JSON. Error envelope:

```json
{
  "code": "bad_request",
  "message": "human-friendly text",
  "request_id": "16-hex-bytes"
}
```

## Public

### `POST /v1/subscribers`

Rate limit: `RATE_LIMIT_SUBSCRIBERS_PER_MIN` per IP.

Request body:

```json
{ "email": "alice@example.org", "source": "footer" }
```

Response (always, including duplicate/invalid):

```json
{ "status": "accepted", "message": "If the address is valid, a confirmation email is on its way." }
```

Notes:
- HTTP status is always `202`.
- A confirmation email is sent only if the email is parse-valid and the row is freshly pending. Existing confirmed/unsubscribed rows are not re-emailed (no enumeration).

### `GET /v1/subscribers/confirm?token=…`

Rate limit: `RATE_LIMIT_CONFIRM_PER_MIN` per IP.

- `200` `{"status":"confirmed"}` on success (idempotent).
- `400` `{"code":"bad_request","message":"invalid or expired token"}` on bad/expired/mismatched-purpose tokens.

### `GET /v1/subscribers/unsubscribe?token=…`

Rate limit: `RATE_LIMIT_DEFAULT_PER_MIN` per IP.

- `200` `{"status":"unsubscribed"}` on success (idempotent).
- `400` on bad token.

The corresponding email carries `List-Unsubscribe` and `List-Unsubscribe-Post: List-Unsubscribe=One-Click` headers; this endpoint is what those headers point at.

## Authenticated

`Authorization: Bearer <supabase-jwt>` required.

### `GET /v1/me/subscription`

Returns the calling user's subscription status:

```json
{ "status": "confirmed" }   // or "pending", "unsubscribed", "none"
```

Read goes through the user pool; Supabase RLS scopes it to the JWT-owner's email.

## Admin (`public.admins` row required)

`Authorization: Bearer <supabase-jwt>` required AND the JWT subject must have a row in `public.admins`.

### `GET /v1/admin/subscribers`

Query params: `limit` (default 50, max 200), `offset`, optional `status=pending|confirmed|unsubscribed`.

```json
{
  "data": [ { "id": "…", "email": "…", "status": "confirmed", "created_at": "…" } ],
  "total": 42,
  "limit": 50,
  "offset": 0
}
```

### `GET /v1/admin/notifications`

Query params: `limit`, `offset`, optional `status=pending|sending|sent|failed|dead`.

```json
{
  "data": [
    {
      "id": "…",
      "kind": "confirm_email",
      "to_email": "…",
      "status": "sent",
      "attempts": 1,
      "last_error": null,
      "next_attempt_at": "…",
      "created_at": "…"
    }
  ],
  "total": 17,
  "limit": 50,
  "offset": 0
}
```

### `POST /v1/admin/subscribers/{id}/resend-confirm`

Re-enqueues a `confirm_email` notification for a `pending` subscriber. Returns `202 {"status":"queued"}` on accept, `409 {"code":"conflict",…}` if the subscriber is already confirmed or unsubscribed.

## Operations

- `GET /healthz` — `200 {"status":"ok"}` always (liveness).
- `GET /readyz` — pings the user pool. `200 {"status":"ready"}` or `503 {"status":"down"}`.
