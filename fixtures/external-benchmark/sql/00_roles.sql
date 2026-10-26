-- External benchmark: the "passwd" row-level security example that appears in the official PostgreSQL
-- documentation (Section "Row Security Policies"). Written independently of this project's other fixtures:
-- the expected behavior comes from the documentation, not from RLS Sentinel's output. SYNTHETIC DATA.
-- Role names are prefixed to avoid clashing with other fixtures.
CREATE ROLE bench_owner NOLOGIN;   -- owns the table (the docs example runs as the table owner)
CREATE ROLE bench_admin NOLOGIN;   -- "Administrator" in the docs
CREATE ROLE bench_bob   NOLOGIN;   -- "Normal user"
CREATE ROLE bench_alice NOLOGIN;   -- "Normal user"
