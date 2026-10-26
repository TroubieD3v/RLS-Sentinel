-- Fixture A: multi-tenant-saas  -- SYNTHETIC DATA ONLY
-- Roles are cluster-global; the harness drops every role created here on teardown.
CREATE ROLE app_owner      NOLOGIN;                       -- owns all objects (the "fixture admin")
CREATE ROLE app_user       NOLOGIN;                       -- group role carrying tenant-user privileges
CREATE ROLE support_reader NOLOGIN;                       -- group role: read-only cross-tenant support access
CREATE ROLE app_alice      NOLOGIN IN ROLE app_user;      -- tenant alpha
CREATE ROLE app_charlie    NOLOGIN IN ROLE app_user;      -- tenant alpha (colleague of alice)
CREATE ROLE app_bob        NOLOGIN IN ROLE app_user;      -- tenant beta
CREATE ROLE app_support    NOLOGIN IN ROLE support_reader;
CREATE ROLE app_anon       NOLOGIN;                       -- anonymous visitor
