-- "secure" = the policies exactly as the documentation describes them.
SET ROLE bench_owner;

-- Administrator can see and change anything.
CREATE POLICY admin_all ON passwd TO bench_admin USING (true) WITH CHECK (true);
-- All users can see all rows.
CREATE POLICY user_sel_policy ON passwd FOR SELECT USING (true);
-- Normal users can update their own records, but limiting which shells a normal user can set.
CREATE POLICY user_mod_policy ON passwd FOR UPDATE
    USING (current_user = user_name)
    WITH CHECK (current_user = user_name AND shell IN ('/bin/bash', '/bin/sh', '/bin/dash', '/bin/zsh', '/bin/tcsh'));

RESET ROLE;
