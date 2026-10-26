-- Schema shared by both variants. Objects are owned by app_owner (NOT a superuser, NOT BYPASSRLS).
GRANT USAGE, CREATE ON SCHEMA public TO app_owner;
GRANT USAGE ON SCHEMA public TO app_user, support_reader, app_anon;

SET ROLE app_owner;

CREATE TABLE organizations (
    id   uuid PRIMARY KEY,
    slug text NOT NULL UNIQUE,
    name text NOT NULL
);

CREATE TABLE memberships (
    id        uuid PRIMARY KEY,
    org_id    uuid NOT NULL REFERENCES organizations (id),
    user_name name NOT NULL,                 -- database role of the member
    role      text NOT NULL DEFAULT 'member',
    UNIQUE (org_id, user_name)
);

CREATE TABLE projects (
    id        uuid PRIMARY KEY,
    org_id    uuid NOT NULL REFERENCES organizations (id),
    name      text NOT NULL,
    is_public boolean NOT NULL DEFAULT false
);

CREATE TABLE invoices (
    id            uuid PRIMARY KEY,
    org_id        uuid NOT NULL REFERENCES organizations (id),
    number        text NOT NULL,
    amount_cents  integer NOT NULL,
    status        text NOT NULL DEFAULT 'open',
    internal_note text                       -- support-only column
);

CREATE TABLE comments (
    id         uuid PRIMARY KEY,
    org_id     uuid NOT NULL REFERENCES organizations (id),
    project_id uuid NOT NULL REFERENCES projects (id),
    author     name NOT NULL,
    body       text NOT NULL
);

CREATE TABLE documents (
    id             uuid PRIMARY KEY,
    org_id         uuid NOT NULL REFERENCES organizations (id),
    title          text NOT NULL,
    classification text NOT NULL DEFAULT 'internal',
    body           text NOT NULL DEFAULT ''
);

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships   ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects      ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices      ENABLE ROW LEVEL SECURITY;
ALTER TABLE comments      ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents     ENABLE ROW LEVEL SECURITY;

-- SQL privileges (the first gate). RLS (the second gate) is defined per variant.
GRANT SELECT ON organizations, memberships TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON projects, comments, documents TO app_user;
GRANT SELECT (id, org_id, number, amount_cents, status) ON invoices TO app_user;  -- internal_note withheld
GRANT INSERT, UPDATE, DELETE ON invoices TO app_user;
GRANT SELECT ON invoices, projects, documents, organizations TO support_reader;
GRANT SELECT ON projects TO app_anon;

RESET ROLE;
