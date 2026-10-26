-- VULNERABLE variant: seven intentional authorization defects (each is annotated).
SET ROLE app_owner;

CREATE POLICY org_member_read ON organizations FOR SELECT TO app_user
    USING (id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user));

CREATE POLICY membership_self ON memberships FOR SELECT TO app_user
    USING (user_name = current_user);

CREATE POLICY projects_tenant ON projects FOR ALL TO app_user
    USING      (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user))
    WITH CHECK (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user));
CREATE POLICY projects_support_read ON projects FOR SELECT TO support_reader USING (true);
-- DEFECT 3 (RLS-005): UPDATE policy with WITH CHECK (true). Because DEFECT 1 below makes every project row visible
-- through the SELECT policy, nothing re-checks the new row: a member can re-assign their project to another tenant.
CREATE POLICY projects_update_loose ON projects FOR UPDATE TO app_user
    USING (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user)) WITH CHECK (true);
-- DEFECT 1 (RLS-003 / RLS-015): a permissive SELECT policy for PUBLIC with USING (true) exposes every
-- project (including non-public ones) to the anonymous role.
CREATE POLICY projects_public_read ON projects FOR SELECT TO PUBLIC USING (true);

CREATE POLICY invoices_select ON invoices FOR SELECT TO app_user
    USING (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user));
-- DEFECT 2 (RLS-005): INSERT policy without a tenant guard - any member may create rows in any tenant.
CREATE POLICY invoices_insert ON invoices FOR INSERT TO app_user WITH CHECK (true);
-- LATENT DEFECT (RLS-005, static only): explicit WITH CHECK (true) on UPDATE. At runtime PostgreSQL ALSO requires the
-- new row to satisfy the SELECT policy when the UPDATE needs SELECT rights, so tenant-scoped SELECT masks this defect on
-- invoices. The harness must NOT report a confirmed violation here (see test bob-cannot-move-own-invoice-to-alpha).
CREATE POLICY invoices_update ON invoices FOR UPDATE TO app_user
    USING (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user))
    WITH CHECK (true);
CREATE POLICY invoices_delete ON invoices FOR DELETE TO app_user
    USING (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user));
CREATE POLICY invoices_support_read ON invoices FOR SELECT TO support_reader USING (true);

CREATE POLICY comments_tenant ON comments FOR ALL TO app_user
    USING      (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user))
    WITH CHECK (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user));
-- DEFECT 4 (RLS-002 / RLS-006): an extra permissive SELECT policy with USING (true) ORs away the tenant filter.
CREATE POLICY comments_select_all ON comments FOR SELECT TO app_user USING (true);
-- DEFECT 5 (RLS-007 / RLS-017): a DELETE policy with USING (true); combined with DEFECT 4 (row visibility)
-- any member can delete any tenant's comments.
CREATE POLICY comments_delete_any ON comments FOR DELETE TO app_user USING (true);

CREATE POLICY documents_select ON documents FOR SELECT TO app_user
    USING (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user));
CREATE POLICY documents_support_read ON documents FOR SELECT TO support_reader USING (true);

CREATE VIEW v_invoices_invoker WITH (security_invoker = true) AS
    SELECT id, org_id, number, amount_cents, status FROM invoices;
-- DEFECT 6 (RLS-008): owner-privileged view. Base-table access runs as app_owner, who owns the table and
-- (without FORCE ROW LEVEL SECURITY) bypasses RLS - the view leaks every tenant's invoices.
CREATE VIEW v_invoices_owner AS
    SELECT id, org_id, number, amount_cents, status FROM invoices;
GRANT SELECT ON v_invoices_invoker, v_invoices_owner TO app_user;

-- DEFECT 7 (RLS-009): SECURITY DEFINER function owned by the table owner, no tenant check, no pinned
-- search_path, EXECUTE left with PUBLIC. It reads invoices with RLS bypassed.
CREATE FUNCTION get_invoice(p_id uuid)
RETURNS TABLE (id uuid, org_id uuid, number text, amount_cents integer, status text)
LANGUAGE sql STABLE SECURITY DEFINER
AS $$ SELECT i.id, i.org_id, i.number, i.amount_cents, i.status FROM public.invoices i WHERE i.id = p_id $$;
GRANT EXECUTE ON FUNCTION get_invoice(uuid) TO app_user;

-- Extra SQL-privilege issue (RLS-014): TRUNCATE is not governed by row policies.
GRANT TRUNCATE ON comments TO app_user;

RESET ROLE;
