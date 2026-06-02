-- +goose Up
-- Newsletter / outreach subscriber list with strict double opt-in.
-- Public users may INSERT a 'pending' row (their own subscribe action), but
-- nothing else. Confirm / unsubscribe happen exclusively via the backend
-- service-role path after a signed token is verified.
CREATE TABLE IF NOT EXISTS public.subscribers (
    id                          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email                       citext UNIQUE NOT NULL,
    status                      text NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ('pending', 'confirmed', 'unsubscribed')),
    confirm_token_hash          bytea,
    confirm_token_expires_at    timestamptz,
    confirmed_at                timestamptz,
    unsubscribed_at             timestamptz,
    source                      text,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now()
);

-- Belt-and-suspenders: even if RLS WITH CHECK were misconfigured, this table-level
-- CHECK guarantees a row inserted as 'pending' has not been pre-confirmed/unsubscribed.
ALTER TABLE public.subscribers
    ADD CONSTRAINT subscribers_pending_clean
    CHECK (
        (status = 'pending'      AND confirmed_at IS NULL AND unsubscribed_at IS NULL)
     OR (status = 'confirmed'    AND confirmed_at IS NOT NULL AND unsubscribed_at IS NULL)
     OR (status = 'unsubscribed' AND unsubscribed_at IS NOT NULL)
    );

CREATE INDEX IF NOT EXISTS subscribers_status_idx ON public.subscribers(status);

ALTER TABLE public.subscribers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subscribers FORCE  ROW LEVEL SECURITY;

-- Anonymous and authenticated users may INSERT a subscribe row, but ONLY in
-- 'pending' state with no confirmed/unsubscribed timestamps. The backend
-- always upserts pending rows on subscribe, then promotes to 'confirmed' via
-- the service-role path after the signed token is verified.
-- Reason: prevents a hostile client from creating an already-confirmed row.
CREATE POLICY subscribers_insert_pending ON public.subscribers
    FOR INSERT
    TO anon, authenticated
    WITH CHECK (
        status = 'pending'
        AND confirmed_at IS NULL
        AND unsubscribed_at IS NULL
    );
COMMENT ON POLICY subscribers_insert_pending ON public.subscribers IS
    'Anon/authenticated may insert only pending rows; confirmation happens server-side.';

-- Authenticated user can SELECT only their own subscription, matched by JWT email.
-- Reason: lets a logged-in user see "am I subscribed?" without exposing the list.
CREATE POLICY subscribers_select_owner ON public.subscribers
    FOR SELECT
    TO authenticated
    USING (
        lower(email::text) = lower(coalesce(auth.jwt() ->> 'email', ''))
    );
COMMENT ON POLICY subscribers_select_owner ON public.subscribers IS
    'Authenticated users see only their own row, matched by JWT email claim.';

-- Admins can SELECT all subscribers via the admins table check.
-- Reason: needed for admin dashboards; RLS gates this not the application layer.
CREATE POLICY subscribers_select_admin ON public.subscribers
    FOR SELECT
    TO authenticated
    USING (EXISTS (SELECT 1 FROM public.admins a WHERE a.user_id = auth.uid()));
COMMENT ON POLICY subscribers_select_admin ON public.subscribers IS
    'Admins (rows in public.admins) may read all subscribers.';

-- No UPDATE/DELETE policy → blocked for anon/authenticated.
-- Confirm + unsubscribe flow through backend service-role after token verification.

-- +goose Down
DROP POLICY IF EXISTS subscribers_select_admin    ON public.subscribers;
DROP POLICY IF EXISTS subscribers_select_owner    ON public.subscribers;
DROP POLICY IF EXISTS subscribers_insert_pending  ON public.subscribers;
DROP TABLE IF EXISTS public.subscribers;
