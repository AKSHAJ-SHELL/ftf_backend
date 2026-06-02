-- name: IsAdmin :one
SELECT EXISTS (
    SELECT 1 FROM public.admins WHERE user_id = $1
) AS is_admin;

-- name: AddAdmin :exec
INSERT INTO public.admins (user_id)
VALUES ($1)
ON CONFLICT (user_id) DO NOTHING;

-- name: RemoveAdmin :exec
DELETE FROM public.admins WHERE user_id = $1;
