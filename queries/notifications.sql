-- name: EnqueueNotification :one
INSERT INTO public.notifications (kind, to_email, payload)
VALUES ($1, $2, $3)
RETURNING id;

-- name: ClaimDueNotifications :many
-- Workers call this with FOR UPDATE SKIP LOCKED so multiple workers do not
-- claim the same row. The same UPDATE flips the row to 'sending' and grants
-- a short lease so a crashed worker's row becomes available again.
WITH due AS (
    SELECT id
      FROM public.notifications
     WHERE status = 'pending'
       AND next_attempt_at <= now()
       AND (locked_until IS NULL OR locked_until <= now())
     ORDER BY next_attempt_at
     LIMIT $1
     FOR UPDATE SKIP LOCKED
)
UPDATE public.notifications n
   SET status       = 'sending',
       attempts     = n.attempts + 1,
       locked_until = now() + (sqlc.arg('lease_seconds')::int * interval '1 second'),
       updated_at   = now()
  FROM due
 WHERE n.id = due.id
RETURNING n.id, n.kind, n.to_email, n.payload, n.attempts;

-- name: MarkNotificationSent :exec
UPDATE public.notifications
   SET status       = 'sent',
       locked_until = NULL,
       last_error   = NULL,
       updated_at   = now()
 WHERE id = $1;

-- name: ScheduleNotificationRetry :exec
UPDATE public.notifications
   SET status          = 'pending',
       next_attempt_at = $2,
       last_error      = $3,
       locked_until    = NULL,
       updated_at      = now()
 WHERE id = $1;

-- name: MarkNotificationFailed :exec
-- Permanent failure for a non-retryable reason (e.g. malformed payload,
-- unsupported kind). Distinct from `dead`, which means we exhausted retries.
UPDATE public.notifications
   SET status       = 'failed',
       locked_until = NULL,
       last_error   = $2,
       updated_at   = now()
 WHERE id = $1;

-- name: MarkNotificationDead :exec
UPDATE public.notifications
   SET status       = 'dead',
       locked_until = NULL,
       last_error   = $2,
       updated_at   = now()
 WHERE id = $1;

-- name: HasRecentNotificationForEmail :one
-- Per-email throttle. Returns true if a notification of the same kind for the
-- same recipient was created within the supplied window. Used to prevent
-- list-bombing via the public subscribe endpoint.
SELECT EXISTS (
    SELECT 1 FROM public.notifications
     WHERE to_email = $1
       AND kind = $2
       AND created_at > now() - (sqlc.arg('window_seconds')::int * interval '1 second')
       AND status IN ('pending','sending','sent')
) AS recent;

-- name: CountSendsLastDay :one
-- Global daily send-cap counter used by the worker to refuse outbound sends
-- when we have already sent a configured number of messages in the last 24h.
SELECT count(*)::bigint AS total
FROM public.notifications
WHERE status = 'sent'
  AND updated_at > now() - interval '1 day';

-- name: ListNotifications :many
SELECT id, kind, to_email, status, attempts, last_error, next_attempt_at, created_at
FROM public.notifications
WHERE (sqlc.narg('status_filter')::text IS NULL OR status = sqlc.narg('status_filter')::text)
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountNotifications :one
SELECT count(*)::bigint AS total
FROM public.notifications
WHERE (sqlc.narg('status_filter')::text IS NULL OR status = sqlc.narg('status_filter')::text);
