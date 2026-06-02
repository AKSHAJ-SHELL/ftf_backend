-- name: UpsertPendingSubscriber :one
-- Insert a pending row or refresh an existing pending one with a new confirm token.
-- Already-confirmed and unsubscribed rows are NOT modified so we cannot leak status
-- to the caller via different errors.
INSERT INTO public.subscribers (email, status, confirm_token_hash, confirm_token_expires_at, source, user_id)
VALUES ($1, 'pending', $2, $3, $4, $5)
ON CONFLICT (email) DO UPDATE
   SET confirm_token_hash       = EXCLUDED.confirm_token_hash,
       confirm_token_expires_at = EXCLUDED.confirm_token_expires_at,
       source                   = COALESCE(public.subscribers.source, EXCLUDED.source),
       user_id                  = COALESCE(public.subscribers.user_id, EXCLUDED.user_id),
       updated_at               = now()
   WHERE public.subscribers.status = 'pending'
RETURNING id, email, status, confirm_token_hash, confirm_token_expires_at, confirmed_at, unsubscribed_at;

-- name: GetSubscriberByEmail :one
SELECT id, email, status, confirm_token_hash, confirm_token_expires_at,
       confirmed_at, unsubscribed_at, source, created_at, updated_at
FROM public.subscribers
WHERE email = $1;

-- name: GetSubscriberByID :one
SELECT id, email, status, confirm_token_hash, confirm_token_expires_at,
       confirmed_at, unsubscribed_at, source, created_at, updated_at
FROM public.subscribers
WHERE id = $1;

-- name: GetSubscriberByConfirmTokenHash :one
-- Indexed lookup used by the confirm flow. Only pending rows match.
SELECT id, email, confirm_token_expires_at
FROM public.subscribers
WHERE confirm_token_hash = $1
  AND status = 'pending'
LIMIT 1;

-- name: ConfirmSubscriberByID :execrows
-- Idempotent: re-confirmation is a no-op once already confirmed.
UPDATE public.subscribers
   SET status                  = 'confirmed',
       confirmed_at            = COALESCE(confirmed_at, now()),
       confirm_token_hash      = NULL,
       confirm_token_expires_at = NULL,
       updated_at              = now()
 WHERE id = $1
   AND status IN ('pending','confirmed')
   AND unsubscribed_at IS NULL;

-- name: UnsubscribeByID :execrows
-- Idempotent. Unsubscribing wipes any confirm token. The WHERE filter ensures
-- already-unsubscribed rows return 0 rows-affected so the caller can detect
-- the no-op explicitly.
UPDATE public.subscribers
   SET status                  = 'unsubscribed',
       unsubscribed_at         = now(),
       confirm_token_hash      = NULL,
       confirm_token_expires_at = NULL,
       updated_at              = now()
 WHERE id = $1
   AND status <> 'unsubscribed';

-- name: ListSubscribers :many
SELECT id, email, status, confirmed_at, unsubscribed_at, source, created_at
FROM public.subscribers
WHERE (sqlc.narg('status_filter')::text IS NULL OR status = sqlc.narg('status_filter')::text)
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountSubscribers :one
SELECT count(*)::bigint AS total
FROM public.subscribers
WHERE (sqlc.narg('status_filter')::text IS NULL OR status = sqlc.narg('status_filter')::text);
