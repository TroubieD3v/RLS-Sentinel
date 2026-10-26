GRANT USAGE, CREATE ON SCHEMA public TO pp_owner;
GRANT USAGE ON SCHEMA public TO pp_staff, pp_editors, pp_outsider, pp_bypass;
SET ROLE pp_owner;

-- Mapping table used by policies. RLS intentionally DISABLED (it is not a tenant-protected table).
CREATE TABLE staff (
    role_name name PRIMARY KEY,
    org       text NOT NULL
);

CREATE TABLE articles (
    id         uuid PRIMARY KEY,
    org        text NOT NULL,
    title      text NOT NULL,
    visibility text NOT NULL CHECK (visibility IN ('public', 'internal')),
    archived   boolean NOT NULL DEFAULT false,
    legal_hold boolean NOT NULL DEFAULT false,
    body       text NOT NULL DEFAULT ''
);

CREATE TABLE ledger (
    id     uuid PRIMARY KEY,
    org    text NOT NULL,
    amount integer NOT NULL
);

-- A table whose only policy is RESTRICTIVE (secure variant): a restrictive policy alone never grants access.
CREATE TABLE locked (
    id   uuid PRIMARY KEY,
    note text NOT NULL
);

ALTER TABLE articles ENABLE ROW LEVEL SECURITY;
ALTER TABLE ledger   ENABLE ROW LEVEL SECURITY;
ALTER TABLE locked   ENABLE ROW LEVEL SECURITY;

GRANT SELECT ON staff TO PUBLIC;
GRANT SELECT ON articles TO PUBLIC;
GRANT INSERT, UPDATE, DELETE ON articles TO pp_editors;
GRANT SELECT ON ledger TO pp_staff, pp_bypass;
GRANT SELECT ON locked TO PUBLIC;

RESET ROLE;
