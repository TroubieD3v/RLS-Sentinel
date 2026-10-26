GRANT USAGE, CREATE ON SCHEMA public TO bench_owner;
GRANT USAGE ON SCHEMA public TO bench_admin, bench_bob, bench_alice;
SET ROLE bench_owner;

CREATE TABLE passwd (
    user_name  text UNIQUE NOT NULL,
    pwhash     text,
    uid        int PRIMARY KEY,
    gid        int NOT NULL,
    real_name  text NOT NULL,
    home_phone text,
    extra_info text,
    home_dir   text NOT NULL,
    shell      text NOT NULL
);

ALTER TABLE passwd ENABLE ROW LEVEL SECURITY;

-- Privileges as described in the documentation example.
GRANT SELECT, INSERT, UPDATE, DELETE ON passwd TO bench_admin;
GRANT SELECT (user_name, uid, gid, real_name, home_phone, extra_info, home_dir, shell) ON passwd TO PUBLIC;
GRANT UPDATE (pwhash, real_name, home_phone, extra_info, shell) ON passwd TO PUBLIC;

RESET ROLE;
