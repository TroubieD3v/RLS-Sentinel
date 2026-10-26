-- "vulnerable" = three hand-made MUTATIONS of the documented policy set.
SET ROLE bench_owner;

CREATE POLICY admin_all ON passwd TO bench_admin USING (true) WITH CHECK (true);
CREATE POLICY user_sel_policy ON passwd FOR SELECT USING (true);
-- MUTATION 1: ownership test removed from USING -> any user may update any row.
-- MUTATION 2: the allowed-shell list removed from WITH CHECK -> arbitrary shells (e.g. /bin/evil) accepted.
CREATE POLICY user_mod_policy ON passwd FOR UPDATE USING (true) WITH CHECK (true);
-- MUTATION 3: an extra privilege that the documentation example does not grant.
SET ROLE bench_owner;
GRANT UPDATE (gid) ON passwd TO PUBLIC;

RESET ROLE;
