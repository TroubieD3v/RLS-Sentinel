-- Fixture C: saas-auth-context (Supabase-style roles). SYNTHETIC / TEST MODE ONLY.
-- Claims are injected with set_config() by the harness; this does NOT prove that an application authenticates users.
CREATE ROLE sb_owner     NOLOGIN;              -- owns objects (not BYPASSRLS)
CREATE ROLE anon         NOLOGIN;              -- unauthenticated API role
CREATE ROLE authenticated NOLOGIN;             -- every signed-in end user shares this DB role
CREATE ROLE service_role NOLOGIN BYPASSRLS;    -- bypasses RLS: must never be used as a simulated end user
