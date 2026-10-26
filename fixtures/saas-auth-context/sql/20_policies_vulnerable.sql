-- VULNERABLE variant: two identity-context defects.
SET ROLE sb_owner;

CREATE POLICY profiles_select_own ON profiles FOR SELECT TO authenticated USING (id = auth.uid());
CREATE POLICY profiles_update_own ON profiles FOR UPDATE TO authenticated
    USING (id = auth.uid()) WITH CHECK (id = auth.uid());

-- DEFECT 1 (RLS-019 / RLS-013): "OR auth.uid() IS NULL" was added so that background jobs keep working. A request
-- that carries NO subject claim (missing/lost identity context) now sees every user's todos.
CREATE POLICY todos_owner ON todos FOR ALL TO authenticated
    USING      (owner_id = auth.uid() OR auth.uid() IS NULL)
    WITH CHECK (owner_id = auth.uid());

CREATE POLICY team_notes_org ON team_notes FOR ALL TO authenticated
    USING      (org_id::text = auth.jwt() ->> 'org_id')
    WITH CHECK (org_id::text = auth.jwt() ->> 'org_id');

-- DEFECT 2 (RLS-013): the policy trusts the custom setting app.current_org. Any session that can run SQL can set it
-- (set_config / SET are available to every role), so it is not a trustworthy identity source.
CREATE POLICY legacy_notes_org ON legacy_notes FOR ALL TO authenticated
    USING      (org_id::text = current_setting('app.current_org', true))
    WITH CHECK (org_id::text = current_setting('app.current_org', true));

RESET ROLE;
