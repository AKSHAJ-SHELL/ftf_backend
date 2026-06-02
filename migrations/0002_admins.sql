-- +goose Up
-- The `admins` table is the source of truth for admin authority.
-- The JWT may carry a hint claim for fast middleware checks, but RLS
-- policies always re-verify against this table so a stale or forged claim
-- cannot grant access.
CREATE TABLE IF NOT EXISTS public.admins (
    user_id    uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.admins ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admins FORCE  ROW LEVEL SECURITY;

-- Authenticated users can read their OWN admin row only.
-- This lets the backend cheaply check "am I an admin?" without exposing the list.
-- Reason: prevents enumeration of who else is an admin.
CREATE POLICY admins_select_self ON public.admins
    FOR SELECT
    TO authenticated
    USING (auth.uid() = user_id);
COMMENT ON POLICY admins_select_self ON public.admins IS
    'Authenticated users may read only their own admin row. No anon/public access.';

-- No INSERT/UPDATE/DELETE policy → only service_role can mutate this table.
-- Admins are provisioned via SQL or a future ops endpoint hitting the service pool.

-- +goose Down
DROP POLICY IF EXISTS admins_select_self ON public.admins;
DROP TABLE IF EXISTS public.admins;
