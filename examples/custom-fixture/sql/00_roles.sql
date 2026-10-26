-- SYNTHETIC EXAMPLE. Roles are NOLOGIN: the harness reaches them with SET ROLE.
CREATE ROLE ex_owner NOLOGIN;
CREATE ROLE ex_alice NOLOGIN;
CREATE ROLE ex_bob   NOLOGIN;
GRANT USAGE, CREATE ON SCHEMA public TO ex_owner;
GRANT USAGE ON SCHEMA public TO ex_alice, ex_bob;
