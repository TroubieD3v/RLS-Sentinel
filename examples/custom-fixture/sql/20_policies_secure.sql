SET ROLE ex_owner;
CREATE POLICY notes_select ON notes FOR SELECT TO ex_alice, ex_bob USING (owner = current_user);
CREATE POLICY notes_insert ON notes FOR INSERT TO ex_alice, ex_bob WITH CHECK (owner = current_user);
CREATE POLICY notes_update ON notes FOR UPDATE TO ex_alice, ex_bob USING (owner = current_user) WITH CHECK (owner = current_user);
CREATE POLICY notes_delete ON notes FOR DELETE TO ex_alice, ex_bob USING (owner = current_user);
RESET ROLE;
