-- SECURE variant: every policy is bounded by tenant membership; views are security_invoker.
SET ROLE app_owner;

CREATE POLICY org_member_read ON organizations FOR SELECT TO app_user
    USING (id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user));

CREATE POLICY membership_self ON memberships FOR SELECT TO app_user
    USING (user_name = current_user);

CREATE POLICY projects_tenant ON projects FOR ALL TO app_user
    USING      (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user))
    WITH CHECK (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user));
CREATE POLICY projects_support_read ON projects FOR SELECT TO support_reader USING (true);
CREATE POLICY projects_anon_public  ON projects FOR SELECT TO app_anon USING (is_public);

CREATE POLICY invoices_select ON invoices FOR SELECT TO app_user
    USING (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user));
CREATE POLICY invoices_insert ON invoices FOR INSERT TO app_user
    WITH CHECK (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user));
CREATE POLICY invoices_update ON invoices FOR UPDATE TO app_user
    USING      (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user))
    WITH CHECK (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user));
CREATE POLICY invoices_delete ON invoices FOR DELETE TO app_user
    USING (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user));
CREATE POLICY invoices_support_read ON invoices FOR SELECT TO support_reader USING (true);

CREATE POLICY comments_tenant ON comments FOR ALL TO app_user
    USING      (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user))
    WITH CHECK (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user));

-- documents: members may READ their tenant's documents. There is intentionally NO write policy:
-- with RLS enabled and no applicable INSERT/UPDATE/DELETE policy, writes are denied by default.
CREATE POLICY documents_select ON documents FOR SELECT TO app_user
    USING (org_id IN (SELECT m.org_id FROM memberships m WHERE m.user_name = current_user));
CREATE POLICY documents_support_read ON documents FOR SELECT TO support_reader USING (true);

-- Views: the security_invoker view evaluates the base table with the CALLER's privileges and RLS.
CREATE VIEW v_invoices_invoker WITH (security_invoker = true) AS
    SELECT id, org_id, number, amount_cents, status FROM invoices;
CREATE VIEW v_invoices_owner WITH (security_invoker = true) AS      -- fixed in this variant
    SELECT id, org_id, number, amount_cents, status FROM invoices;
GRANT SELECT ON v_invoices_invoker, v_invoices_owner TO app_user;

-- Function runs with the caller's rights, so RLS applies.
CREATE FUNCTION get_invoice(p_id uuid)
RETURNS TABLE (id uuid, org_id uuid, number text, amount_cents integer, status text)
LANGUAGE sql STABLE SECURITY INVOKER
AS $$ SELECT i.id, i.org_id, i.number, i.amount_cents, i.status FROM public.invoices i WHERE i.id = p_id $$;
REVOKE EXECUTE ON FUNCTION get_invoice(uuid) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION get_invoice(uuid) TO app_user;

RESET ROLE;
