-- +goose Up
-- Durable outbound notification queue. Workers claim rows with
-- `FOR UPDATE SKIP LOCKED` and a `locked_until` lease.
CREATE TABLE IF NOT EXISTS public.notifications (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind            text NOT NULL,
    to_email        citext NOT NULL,
    payload         jsonb NOT NULL DEFAULT '{}'::jsonb,
    status          text NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending','sending','sent','failed','dead')),
    attempts        int  NOT NULL DEFAULT 0,
    last_error      text,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    locked_until    timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS notifications_ready_idx
    ON public.notifications(status, next_attempt_at)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS notifications_locked_idx
    ON public.notifications(locked_until)
    WHERE locked_until IS NOT NULL;

ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notifications FORCE  ROW LEVEL SECURITY;

-- No anon/authenticated INSERT/UPDATE/DELETE policy → service_role only.
-- Writes happen via the backend service-role pool (subscribe enqueue, worker updates).

-- Admins can SELECT for observability dashboards.
CREATE POLICY notifications_select_admin ON public.notifications
    FOR SELECT
    TO authenticated
    USING (EXISTS (SELECT 1 FROM public.admins a WHERE a.user_id = auth.uid()));
COMMENT ON POLICY notifications_select_admin ON public.notifications IS
    'Admins may read all notification rows for operational visibility.';

-- +goose Down
DROP POLICY IF EXISTS notifications_select_admin ON public.notifications;
DROP TABLE IF EXISTS public.notifications;
