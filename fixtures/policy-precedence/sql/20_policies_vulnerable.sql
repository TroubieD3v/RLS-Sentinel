-- VULNERABLE variant: restrictive intent expressed with PERMISSIVE policies; owner not forced.
SET ROLE pp_owner;

CREATE POLICY art_public_read ON articles AS PERMISSIVE FOR SELECT TO PUBLIC USING (visibility = 'public');
CREATE POLICY art_staff_read  ON articles AS PERMISSIVE FOR SELECT TO pp_staff
    USING (org IN (SELECT s.org FROM staff s WHERE s.role_name = current_user));
-- DEFECT 1 (RLS-011): intended as a restrictive "hide archived rows" rule, but CREATE POLICY defaults to PERMISSIVE,
-- so it is OR-ed with the other policies and no longer restricts anything.
CREATE POLICY art_not_archived ON articles FOR SELECT TO PUBLIC USING (NOT archived);

CREATE POLICY art_editor_insert ON articles AS PERMISSIVE FOR INSERT TO pp_editors
    WITH CHECK (org IN (SELECT s.org FROM staff s WHERE s.role_name = current_user));
CREATE POLICY art_editor_update ON articles AS PERMISSIVE FOR UPDATE TO pp_editors
    USING      (org IN (SELECT s.org FROM staff s WHERE s.role_name = current_user))
    WITH CHECK (org IN (SELECT s.org FROM staff s WHERE s.role_name = current_user));
CREATE POLICY art_editor_delete ON articles AS PERMISSIVE FOR DELETE TO pp_editors
    USING (org IN (SELECT s.org FROM staff s WHERE s.role_name = current_user));
-- DEFECT 2 (RLS-011): same mistake for legal hold - these "hold" policies are PERMISSIVE and therefore GRANT access.
CREATE POLICY art_hold_update ON articles FOR UPDATE TO PUBLIC USING (NOT legal_hold) WITH CHECK (NOT legal_hold);
CREATE POLICY art_hold_delete ON articles FOR DELETE TO PUBLIC USING (NOT legal_hold);

CREATE POLICY ledger_staff_read ON ledger FOR SELECT TO pp_staff
    USING (org IN (SELECT s.org FROM staff s WHERE s.role_name = current_user));
-- DEFECT 3 (RLS-004): no FORCE ROW LEVEL SECURITY, so the table owner reads every row.

-- DEFECT 4 (RLS-011): a PERMISSIVE policy where a restrictive-only guard was intended - everybody reads 'locked'.
CREATE POLICY locked_open ON locked AS PERMISSIVE FOR SELECT TO PUBLIC USING (true);

RESET ROLE;
