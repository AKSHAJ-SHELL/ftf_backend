-- name: InsertEmailLog :exec
INSERT INTO public.email_log (notification_id, to_email_hash, provider, provider_message_id, status, error)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ListEmailLog :many
SELECT id, notification_id, to_email_hash, provider, provider_message_id, status, error, created_at
FROM public.email_log
WHERE (sqlc.narg('status_filter')::text IS NULL OR status = sqlc.narg('status_filter')::text)
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;
