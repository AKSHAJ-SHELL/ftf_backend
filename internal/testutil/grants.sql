-- Apply AFTER production migrations + auth shim, in tests only.
-- Mirrors the production grant posture after migration 0006: anon/authenticated
-- have only the specific privileges RLS expects, NOT a blanket GRANT ALL.
-- Test code that needs to bypass RLS should use the service_role role.

REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM anon, authenticated;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM anon, authenticated;

GRANT INSERT, UPDATE, SELECT ON public.subscribers   TO anon, authenticated;
GRANT SELECT                ON public.admins         TO authenticated;
GRANT SELECT                ON public.notifications  TO authenticated;
GRANT SELECT                ON public.email_log      TO authenticated;

GRANT ALL ON ALL TABLES    IN SCHEMA public TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO service_role;
