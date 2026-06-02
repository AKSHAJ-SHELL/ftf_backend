-- +goose Up
-- Post-audit hardening: tighten grants, add an UPDATE policy for the
-- pending-row upsert, index the confirm token hash, link subscribers to
-- auth.users when an authenticated user subscribes, and add an admin
-- DELETE policy on the email_log for retention sweeps.

-- ---------------------------------------------------------------------------
-- M8: Remove Supabase's default GRANT ALL to anon/authenticated.
-- ---------------------------------------------------------------------------
-- Supabase's PostgREST-style defaults broadly GRANT on public.*. RLS is the
-- only gate that prevents this. Revoke and grant back only what we use.
REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM anon, authenticated;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon, authenticated;

-- subscribers: anon needs INSERT (subscribe) and UPDATE (re-subscribe pending
-- token rotation). authenticated additionally reads their own row + admin
-- reads via RLS. No DELETE for either.
GRANT INSERT, UPDATE, SELECT ON public.subscribers TO anon, authenticated;

-- admins: authenticated reads its own row. Anon has no access.
GRANT SELECT ON public.admins TO authenticated;

-- notifications + email_log: admin SELECT via RLS only. No anon access.
GRANT SELECT ON public.notifications TO authenticated;
GRANT SELECT ON public.email_log     TO authenticated;

-- service_role keeps full access (it BYPASSRLS anyway, but the GRANT keeps
-- the connection role's catalog visibility intact).
GRANT ALL ON ALL TABLES    IN SCHEMA public TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO service_role;

-- ---------------------------------------------------------------------------
-- C4: Index for confirm-token lookup.
-- ---------------------------------------------------------------------------
-- Replaces an O(N) full-table scan in HandleConfirm with an indexed lookup.
-- Partial index keeps the index small: only pending rows ever carry a token.
CREATE INDEX IF NOT EXISTS subscribers_confirm_token_hash_idx
    ON public.subscribers(confirm_token_hash)
    WHERE confirm_token_hash IS NOT NULL;

-- ---------------------------------------------------------------------------
-- C1: UPDATE policy so anon's upsert can refresh an existing pending row.
-- ---------------------------------------------------------------------------
-- The public subscribe handler now uses the user pool with role=anon. The
-- INSERT half is covered by subscribers_insert_pending. The ON CONFLICT
-- UPDATE half needs an UPDATE policy. We restrict the USING and WITH CHECK
-- so an attacker cannot UPDATE a confirmed/unsubscribed row, nor flip status.
CREATE POLICY subscribers_update_pending ON public.subscribers
    FOR UPDATE
    TO anon, authenticated
    USING (
        status = 'pending'
        AND confirmed_at IS NULL
        AND unsubscribed_at IS NULL
    )
    WITH CHECK (
        status = 'pending'
        AND confirmed_at IS NULL
        AND unsubscribed_at IS NULL
    );
COMMENT ON POLICY subscribers_update_pending ON public.subscribers IS
    'Allow refreshing a pending row''s confirm token only; cannot flip status, cannot touch confirmed/unsubscribed rows.';

-- ---------------------------------------------------------------------------
-- M6: Link subscribers to auth.users when an authenticated user subscribed.
-- ---------------------------------------------------------------------------
-- The previous select policy keyed on the JWT email string only, so an email
-- change in Supabase silently revoked a user's visibility of their own row.
-- Add a nullable user_id and OR the SELECT policy with auth.uid().
ALTER TABLE public.subscribers
    ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES auth.users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS subscribers_user_id_idx
    ON public.subscribers(user_id)
    WHERE user_id IS NOT NULL;

DROP POLICY IF EXISTS subscribers_select_owner ON public.subscribers;
CREATE POLICY subscribers_select_owner ON public.subscribers
    FOR SELECT
    TO authenticated
    USING (
        (user_id IS NOT NULL AND user_id = auth.uid())
        OR lower(email::text) = lower(coalesce(auth.jwt() ->> 'email', ''))
    );
COMMENT ON POLICY subscribers_select_owner ON public.subscribers IS
    'Authenticated users see their own row, matched by user_id (stable) or JWT email (fallback for legacy rows).';

-- ---------------------------------------------------------------------------
-- L3: Admin DELETE policy on email_log to support retention sweeps.
-- ---------------------------------------------------------------------------
-- Real auto-TTL requires pg_cron; this policy lets a scheduled service-role
-- (or a future admin tool) prune old rows without bypassing RLS.
CREATE POLICY email_log_delete_admin ON public.email_log
    FOR DELETE
    TO authenticated
    USING (EXISTS (SELECT 1 FROM public.admins a WHERE a.user_id = auth.uid()));
COMMENT ON POLICY email_log_delete_admin ON public.email_log IS
    'Admins may delete email_log rows (used by retention sweeps).';

-- +goose Down
DROP POLICY IF EXISTS email_log_delete_admin     ON public.email_log;
DROP POLICY IF EXISTS subscribers_select_owner   ON public.subscribers;
-- Restore the original email-only select policy on rollback.
CREATE POLICY subscribers_select_owner ON public.subscribers
    FOR SELECT
    TO authenticated
    USING (lower(email::text) = lower(coalesce(auth.jwt() ->> 'email', '')));
DROP INDEX IF EXISTS public.subscribers_user_id_idx;
ALTER TABLE public.subscribers DROP COLUMN IF EXISTS user_id;
DROP POLICY IF EXISTS subscribers_update_pending ON public.subscribers;
DROP INDEX IF EXISTS public.subscribers_confirm_token_hash_idx;
-- We do NOT restore the original wide-open GRANT ALL on rollback; operators
-- should re-apply Supabase defaults manually if downgrading.
