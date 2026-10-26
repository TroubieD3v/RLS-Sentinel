-- SECURE variant: permissive policies OR together, restrictive policies AND on top.
SET ROLE pp_owner;

-- Everyone (PUBLIC) may read public articles.
CREATE POLICY art_public_read ON articles AS PERMISSIVE FOR SELECT TO PUBLIC USING (visibility = 'public');
-- Staff may also read internal articles of their own org.
CREATE POLICY art_staff_read  ON articles AS PERMISSIVE FOR SELECT TO pp_staff
    USING (org IN (SELECT s.org FROM staff s WHERE s.role_name = current_user));
-- RESTRICTIVE: archived rows are invisible to everyone, whatever the permissive policies say.
CREATE POLICY art_not_archived ON articles AS RESTRICTIVE FOR SELECT TO PUBLIC USING (NOT archived);

CREATE POLICY art_editor_insert ON articles AS PERMISSIVE FOR INSERT TO pp_editors
    WITH CHECK (org IN (SELECT s.org FROM staff s WHERE s.role_name = current_user));
CREATE POLICY art_editor_update ON articles AS PERMISSIVE FOR UPDATE TO pp_editors
    USING      (org IN (SELECT s.org FROM staff s WHERE s.role_name = current_user))
    WITH CHECK (org IN (SELECT s.org FROM staff s WHERE s.role_name = current_user));
CREATE POLICY art_editor_delete ON articles AS PERMISSIVE FOR DELETE TO pp_editors
    USING (org IN (SELECT s.org FROM staff s WHERE s.role_name = current_user));
-- RESTRICTIVE: rows under legal hold can be neither modified nor deleted by anybody.
CREATE POLICY art_hold_update ON articles AS RESTRICTIVE FOR UPDATE TO PUBLIC USING (NOT legal_hold) WITH CHECK (NOT legal_hold);
CREATE POLICY art_hold_delete ON articles AS RESTRICTIVE FOR DELETE TO PUBLIC USING (NOT legal_hold);

-- ledger: tenant read for staff, and the owner is subject to RLS because of FORCE.
CREATE POLICY ledger_staff_read ON ledger FOR SELECT TO pp_staff
    USING (org IN (SELECT s.org FROM staff s WHERE s.role_name = current_user));
ALTER TABLE ledger FORCE ROW LEVEL SECURITY;

-- locked: ONLY a restrictive policy exists -> default deny for everybody.
CREATE POLICY locked_restrictive ON locked AS RESTRICTIVE FOR SELECT TO PUBLIC USING (true);

RESET ROLE;
