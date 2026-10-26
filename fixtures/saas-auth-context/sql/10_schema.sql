CREATE SCHEMA auth AUTHORIZATION sb_owner;
GRANT USAGE ON SCHEMA auth TO anon, authenticated, service_role;
GRANT USAGE, CREATE ON SCHEMA public TO sb_owner;
GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;

SET ROLE sb_owner;

-- Helper functions in the style of Supabase: they read per-request settings that a trusted gateway
-- (PostgREST) sets from a VERIFIED JWT. Inside this fixture the harness plays the gateway.
CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE
AS $$ SELECT nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
CREATE FUNCTION auth.role() RETURNS text LANGUAGE sql STABLE
AS $$ SELECT nullif(current_setting('request.jwt.claim.role', true), '') $$;
CREATE FUNCTION auth.jwt() RETURNS jsonb LANGUAGE sql STABLE
AS $$ SELECT coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $$;
GRANT EXECUTE ON FUNCTION auth.uid(), auth.role(), auth.jwt() TO anon, authenticated, service_role;

CREATE TABLE profiles (
    id           uuid PRIMARY KEY,
    display_name text NOT NULL,
    email        text NOT NULL
);

CREATE TABLE todos (
    id       uuid PRIMARY KEY,
    owner_id uuid NOT NULL,
    title    text NOT NULL,
    done     boolean NOT NULL DEFAULT false
);

-- Tenant data keyed by an org claim inside the JWT.
CREATE TABLE team_notes (
    id     uuid PRIMARY KEY,
    org_id uuid NOT NULL,
    author uuid NOT NULL,
    body   text NOT NULL
);

-- Legacy table whose policy (vulnerable variant) trusts a free-form custom setting.
CREATE TABLE legacy_notes (
    id     uuid PRIMARY KEY,
    org_id uuid NOT NULL,
    body   text NOT NULL
);

ALTER TABLE profiles     ENABLE ROW LEVEL SECURITY;
ALTER TABLE todos        ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_notes   ENABLE ROW LEVEL SECURITY;
ALTER TABLE legacy_notes ENABLE ROW LEVEL SECURITY;

GRANT SELECT, UPDATE ON profiles TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON todos, team_notes, legacy_notes TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON todos, team_notes, legacy_notes, profiles TO service_role;
-- anon has no table privileges at all (denied at the GRANT gate).

RESET ROLE;
