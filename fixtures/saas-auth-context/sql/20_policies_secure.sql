-- SECURE variant: every policy derives identity from auth.uid() / auth.jwt(); a missing claim yields NULL => no rows.
SET ROLE sb_owner;

CREATE POLICY profiles_select_own ON profiles FOR SELECT TO authenticated USING (id = auth.uid());
CREATE POLICY profiles_update_own ON profiles FOR UPDATE TO authenticated
    USING (id = auth.uid()) WITH CHECK (id = auth.uid());

CREATE POLICY todos_owner ON todos FOR ALL TO authenticated
    USING (owner_id = auth.uid()) WITH CHECK (owner_id = auth.uid());

CREATE POLICY team_notes_org ON team_notes FOR ALL TO authenticated
    USING      (org_id::text = auth.jwt() ->> 'org_id')
    WITH CHECK (org_id::text = auth.jwt() ->> 'org_id');

-- Fixed: identity comes from the gateway-set JWT claim, not from a settable free-form variable.
CREATE POLICY legacy_notes_org ON legacy_notes FOR ALL TO authenticated
    USING      (org_id::text = auth.jwt() ->> 'org_id')
    WITH CHECK (org_id::text = auth.jwt() ->> 'org_id');

RESET ROLE;
