-- +goose Up
-- Audit log of email send attempts. Recipient stored as a SHA-256 hash
-- so the log never contains raw email addresses (PII minimization).
CREATE TABLE IF NOT EXISTS public.email_log (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    notification_id     uuid REFERENCES public.notifications(id) ON DELETE SET NULL,
    to_email_hash       bytea NOT NULL,
    provider            text NOT NULL,
    provider_message_id text,
    status              text NOT NULL CHECK (status IN ('sent','failed','dead')),
    error               text,
    created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS email_log_to_email_hash_idx ON public.email_log(to_email_hash);
CREATE INDEX IF NOT EXISTS email_log_status_idx        ON public.email_log(status);
CREATE INDEX IF NOT EXISTS email_log_created_at_idx    ON public.email_log(created_at);

ALTER TABLE public.email_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.email_log FORCE  ROW LEVEL SECURITY;

-- Writes are service-role only (no policy granted).
-- Admins can read for support / debugging.
CREATE POLICY email_log_select_admin ON public.email_log
    FOR SELECT
    TO authenticated
    USING (EXISTS (SELECT 1 FROM public.admins a WHERE a.user_id = auth.uid()));
COMMENT ON POLICY email_log_select_admin ON public.email_log IS
    'Admins may read email send-attempt logs; raw addresses are hashed at write time.';

-- +goose Down
DROP POLICY IF EXISTS email_log_select_admin ON public.email_log;
DROP TABLE IF EXISTS public.email_log;
