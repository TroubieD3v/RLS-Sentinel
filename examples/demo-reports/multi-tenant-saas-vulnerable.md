# RLS Sentinel report — acme-saas

> **PERMISSIONS ARE NOT PROOF. TEST THEM.** Results below describe a tested schema in a disposable database; see Limitations.

- **Environment:** DISPOSABLE LAB · PostgreSQL 18.3 (local)
- **Fixture:** multi-tenant-saas / vulnerable · **Identity:** PostgreSQL roles via SET ROLE from a non-superuser harness login
- **Run:** `4d274fc017d8` · tool 1.0.0 · ruleset 2026.10.1
- **Reproducibility:** schema `sha256:c4d5a706526a7d8538c844e6c3a59f3d9eaba75a2ce8b3e4d11812d1916d7acb` · spec `sha256:41c16c1823ab5a4fa744462e27af52610ed3a5698f465f6f10c96ea7fdf483ac` · fixture `sha256:01dfc82f2eb8f0fb5d7ccb781bab0791153e38dc447b835bb5837fd81473b562`

## Coverage

```text
AUTHORIZATION COVERAGE
──────────────────────────────────────────────────
Expected assertions         :   42
Executed with valid context :   42
PASS                        :   34
FAIL                        :    8
INCONCLUSIVE                :    0
NOT EXECUTED                :    0
Verified coverage           : 100.0% (42 / 42)
──────────────────────────────────────────────────
Verified coverage = (PASS + FAIL) / expected assertions. INCONCLUSIVE, ERROR,
UNSUPPORTED and SKIPPED cases are never counted as verified.
```

Rows read from the database: none retained (`row_contents_retained: false`).

## Summary

| Evidence class | Count |
|---|---|
| CONFIGURATION_RISK | 14 |
| CONFIRMED_VIOLATION | 8 |
| INCONCLUSIVE | 4 |

| Severity | Count |
|---|---|
| Critical | 3 |
| High | 5 |
| Informational | 4 |
| Medium | 13 |
| Needs triage | 1 |

## Findings

### RLS-005 · INSERT / UPDATE missing or ineffective new-row guard

- **Severity:** Critical — Runtime-confirmed unauthorized write across the identity boundary declared in the spec (rolled back in the lab).
- **Evidence class:** CONFIRMED_VIOLATION · **provenance:** RUNTIME_OBSERVATION, USER_EXPECTATION · **confidence:** OBSERVED
- **Subject:** `public.invoices#bob-cannot-insert-invoice-into-alpha`
- **What happened:** bob (app_bob) INSERT public.invoices: Access succeeded although the actor must be denied.
- **Why it matters:** A WITH CHECK expression is absent, constant TRUE or does not bind the tenant column, so a role can create or move rows into a tenant it does not belong to.
- **Expected / observed:** DENY / ROW_INSERTED, rows=1
- **Cases:** bob-cannot-insert-invoice-into-alpha
  - evidence [case] INSERT as app_bob: expected DENY, observed ROW_INSERTED; rows=1; gate=NONE
  - evidence [spec] independent expectation: DENY for actor bob
- **Reproduce (disposable fixture):**

```text
rls-sentinel test --fixture multi-tenant-saas --variant vulnerable --only bob-cannot-insert-invoice-into-alpha
-- as role app_bob (SET ROLE from a non-superuser login that is a member of it):
INSERT INTO "public"."invoices" ("id", "number", "amount_cents", "org_id") VALUES ($1, $2, $3, $4)  -- $1 = 0d88c02f-e999-5586-b026-3feda0d2dbf7, $2 = B-EVIL, $3 = 100, $4 = 11111111-1111-1111-1111-111111111111
```
- **Remediation (review before applying):** Add or tighten WITH CHECK so the new row satisfies the same tenant predicate as USING.
- **Limitations:** Executed in a disposable database against synthetic fixture data; it demonstrates the behaviour of that schema, not of production.
- **References:** <https://www.postgresql.org/docs/current/sql-createpolicy.html>

### RLS-005 · INSERT / UPDATE missing or ineffective new-row guard

- **Severity:** Critical — Runtime-confirmed unauthorized write across the identity boundary declared in the spec (rolled back in the lab).
- **Evidence class:** CONFIRMED_VIOLATION · **provenance:** RUNTIME_OBSERVATION, USER_EXPECTATION · **confidence:** OBSERVED
- **Subject:** `public.projects#bob-cannot-move-own-project-to-alpha`
- **What happened:** bob (app_bob) UPDATE public.projects: Access succeeded although the actor must be denied.
- **Why it matters:** A WITH CHECK expression is absent, constant TRUE or does not bind the tenant column, so a role can create or move rows into a tenant it does not belong to.
- **Expected / observed:** DENY / ROWS_AFFECTED, rows=1
- **Cases:** bob-cannot-move-own-project-to-alpha
  - evidence [case] UPDATE as app_bob: expected DENY, observed ROWS_AFFECTED; rows=1; gate=NONE
  - evidence [spec] independent expectation: DENY for actor bob
- **Reproduce (disposable fixture):**

```text
rls-sentinel test --fixture multi-tenant-saas --variant vulnerable --only bob-cannot-move-own-project-to-alpha
-- as role app_bob (SET ROLE from a non-superuser login that is a member of it):
UPDATE "public"."projects" SET "org_id" = $1 WHERE "id" = $2  -- $1 = 11111111-1111-1111-1111-111111111111, $2 = id:e5081f67
```
- **Remediation (review before applying):** Add or tighten WITH CHECK so the new row satisfies the same tenant predicate as USING.
- **Limitations:** Executed in a disposable database against synthetic fixture data; it demonstrates the behaviour of that schema, not of production.
- **References:** <https://www.postgresql.org/docs/current/sql-createpolicy.html>

### RLS-017 · Accidental all-tenant write by shared role

- **Severity:** Critical — Runtime-confirmed unauthorized write across the identity boundary declared in the spec (rolled back in the lab).
- **Evidence class:** CONFIRMED_VIOLATION · **provenance:** RUNTIME_OBSERVATION, USER_EXPECTATION · **confidence:** OBSERVED
- **Subject:** `public.comments#bob-cannot-delete-alpha-comment`
- **What happened:** bob (app_bob) DELETE public.comments: Access succeeded although the actor must be denied.
- **Why it matters:** A shared (non-tenant-bound) role or group modified rows across tenants in a controlled mutation test.
- **Expected / observed:** DENY / ROWS_AFFECTED, rows=1
- **Cases:** bob-cannot-delete-alpha-comment
  - evidence [case] DELETE as app_bob: expected DENY, observed ROWS_AFFECTED; rows=1; gate=NONE
  - evidence [spec] independent expectation: DENY for actor bob
- **Reproduce (disposable fixture):**

```text
rls-sentinel test --fixture multi-tenant-saas --variant vulnerable --only bob-cannot-delete-alpha-comment
-- as role app_bob (SET ROLE from a non-superuser login that is a member of it):
DELETE FROM "public"."comments" WHERE "id" = $1  -- $1 = id:019a1ee1
```
- **Remediation (review before applying):** Bind write policies to the tenant predicate even for shared or support roles.
- **Limitations:** Executed in a disposable database against synthetic fixture data; it demonstrates the behaviour of that schema, not of production.
- **References:** <https://www.postgresql.org/docs/current/sql-createpolicy.html>

### RLS-006 · Cross-tenant SELECT visibility

- **Severity:** High — Runtime-confirmed read across the identity boundary declared in the spec.
- **Evidence class:** CONFIRMED_VIOLATION · **provenance:** RUNTIME_OBSERVATION, USER_EXPECTATION · **confidence:** OBSERVED
- **Subject:** `public.comments#bob-cannot-read-alpha-comment`
- **What happened:** bob (app_bob) SELECT public.comments: Access succeeded although the actor must be denied.
- **Why it matters:** A role obtained a row that belongs to another tenant (runtime evidence under test roles).
- **Expected / observed:** DENY / ROW_RETURNED, rows=1
- **Cases:** bob-cannot-read-alpha-comment
  - evidence [case] SELECT as app_bob: expected DENY, observed ROW_RETURNED; rows=1; gate=NONE
  - evidence [spec] independent expectation: DENY for actor bob
- **Reproduce (disposable fixture):**

```text
rls-sentinel test --fixture multi-tenant-saas --variant vulnerable --only bob-cannot-read-alpha-comment
-- as role app_bob (SET ROLE from a non-superuser login that is a member of it):
SELECT 1 FROM "public"."comments" WHERE "id" = $1  -- $1 = id:019a1ee1
```
- **Remediation (review before applying):** Constrain every permissive SELECT policy with the tenant predicate; remove constant-TRUE policies.
- **Limitations:** Executed in a disposable database against synthetic fixture data; it demonstrates the behaviour of that schema, not of production.
- **References:** <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>

### RLS-006 · Cross-tenant SELECT visibility

- **Severity:** High — Runtime-confirmed read across the identity boundary declared in the spec.
- **Evidence class:** CONFIRMED_VIOLATION · **provenance:** RUNTIME_OBSERVATION, USER_EXPECTATION · **confidence:** OBSERVED
- **Subject:** `public.projects#bob-cannot-read-alpha-project`
- **What happened:** bob (app_bob) SELECT public.projects: Access succeeded although the actor must be denied.
- **Why it matters:** A role obtained a row that belongs to another tenant (runtime evidence under test roles).
- **Expected / observed:** DENY / ROW_RETURNED, rows=1
- **Cases:** bob-cannot-read-alpha-project
  - evidence [case] SELECT as app_bob: expected DENY, observed ROW_RETURNED; rows=1; gate=NONE
  - evidence [spec] independent expectation: DENY for actor bob
- **Reproduce (disposable fixture):**

```text
rls-sentinel test --fixture multi-tenant-saas --variant vulnerable --only bob-cannot-read-alpha-project
-- as role app_bob (SET ROLE from a non-superuser login that is a member of it):
SELECT 1 FROM "public"."projects" WHERE "id" = $1  -- $1 = id:4ec61757
```
- **Remediation (review before applying):** Constrain every permissive SELECT policy with the tenant predicate; remove constant-TRUE policies.
- **Limitations:** Executed in a disposable database against synthetic fixture data; it demonstrates the behaviour of that schema, not of production.
- **References:** <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>

### RLS-008 · Privileged view exposure with owner-policy context

- **Severity:** High — Runtime-confirmed read across the identity boundary declared in the spec.
- **Evidence class:** CONFIRMED_VIOLATION · **provenance:** RUNTIME_OBSERVATION, USER_EXPECTATION · **confidence:** OBSERVED
- **Subject:** `public.invoices#bob-cannot-read-alpha-invoice-via-owner-view`
- **What happened:** bob (app_bob) SELECT public.invoices via public.v_invoices_owner: Access succeeded although the actor must be denied.
- **Why it matters:** A view without security_invoker runs with its owner's privileges; if the owner bypasses RLS on the base table, the view exposes rows across tenants.
- **Expected / observed:** DENY / ROW_RETURNED, rows=1
- **Cases:** bob-cannot-read-alpha-invoice-via-owner-view
  - evidence [case] SELECT as app_bob: expected DENY, observed ROW_RETURNED; rows=1; gate=NONE
  - evidence [spec] independent expectation: DENY for actor bob
- **Reproduce (disposable fixture):**

```text
rls-sentinel test --fixture multi-tenant-saas --variant vulnerable --only bob-cannot-read-alpha-invoice-via-owner-view
-- as role app_bob (SET ROLE from a non-superuser login that is a member of it):
SELECT 1 FROM "public"."v_invoices_owner" WHERE "id" = $1  -- $1 = id:4242a3bc  -- via owner-privileged view (owner app_owner)
```
- **Remediation (review before applying):** ALTER VIEW &lt;view&gt; SET (security_invoker = true) (PostgreSQL 15+), or move the tenant filter into the view and revoke direct access.
- **Limitations:** Executed in a disposable database against synthetic fixture data; it demonstrates the behaviour of that schema, not of production.
- **References:** <https://www.postgresql.org/docs/current/sql-createview.html> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>

### RLS-009 · SECURITY DEFINER misuse candidate

- **Severity:** High — Runtime-confirmed read across the identity boundary declared in the spec.
- **Evidence class:** CONFIRMED_VIOLATION · **provenance:** RUNTIME_OBSERVATION, USER_EXPECTATION · **confidence:** OBSERVED
- **Subject:** `public.invoices#bob-cannot-read-alpha-invoice-via-function`
- **What happened:** bob (app_bob) EXECUTE public.invoices via public.get_invoice: Access succeeded although the actor must be denied.
- **Why it matters:** A SECURITY DEFINER function owned by a role that bypasses RLS on protected tables is executable by non-owner roles. Not every SECURITY DEFINER function is vulnerable; this is a candidate unless a runtime case confirms leakage.
- **Expected / observed:** DENY / ROW_RETURNED, rows=1
- **Cases:** bob-cannot-read-alpha-invoice-via-function
  - evidence [case] EXECUTE as app_bob: expected DENY, observed ROW_RETURNED; rows=1; gate=NONE
  - evidence [spec] independent expectation: DENY for actor bob
- **Reproduce (disposable fixture):**

```text
rls-sentinel test --fixture multi-tenant-saas --variant vulnerable --only bob-cannot-read-alpha-invoice-via-function
-- as role app_bob (SET ROLE from a non-superuser login that is a member of it):
SELECT * FROM "public"."get_invoice"($1)  -- $1 = id:4242a3bc  -- SECURITY DEFINER function (owner app_owner)
```
- **Remediation (review before applying):** Prefer SECURITY INVOKER; if DEFINER is required, pin search_path, check the caller's tenant inside the function, and REVOKE EXECUTE FROM PUBLIC.
- **Limitations:** Executed in a disposable database against synthetic fixture data; it demonstrates the behaviour of that schema, not of production.
- **References:** <https://www.postgresql.org/docs/current/sql-createfunction.html>

### RLS-015 · Unexpected anonymous access

- **Severity:** High — Runtime-confirmed read by the anonymous identity of data the spec marks private.
- **Evidence class:** CONFIRMED_VIOLATION · **provenance:** RUNTIME_OBSERVATION, USER_EXPECTATION · **confidence:** OBSERVED
- **Subject:** `public.projects#anon-cannot-read-private-project`
- **What happened:** anon (app_anon) SELECT public.projects: Access succeeded although the actor must be denied.
- **Why it matters:** The anonymous/guest identity can read or write rows the spec expects it to be denied.
- **Expected / observed:** DENY / ROW_RETURNED, rows=1
- **Cases:** anon-cannot-read-private-project
  - evidence [case] SELECT as app_anon: expected DENY, observed ROW_RETURNED; rows=1; gate=NONE
  - evidence [spec] independent expectation: DENY for actor anon
- **Reproduce (disposable fixture):**

```text
rls-sentinel test --fixture multi-tenant-saas --variant vulnerable --only anon-cannot-read-private-project
-- as role app_anon (SET ROLE from a non-superuser login that is a member of it):
SELECT 1 FROM "public"."projects" WHERE "id" = $1  -- $1 = id:4ec61757
```
- **Remediation (review before applying):** Remove anonymous grants and PUBLIC policies on private tables; expose only explicitly public rows.
- **Limitations:** Executed in a disposable database against synthetic fixture data; it demonstrates the behaviour of that schema, not of production.
- **References:** <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>

### RLS-002 · Excessively broad permissive policy

- **Severity:** Medium — Constant-TRUE permissive policy reachable by roles the spec expects to be tenant-bounded; not runtime-confirmed.
- **Evidence class:** CONFIGURATION_RISK · **provenance:** CATALOG_FACT, STATIC_INFERENCE, USER_EXPECTATION · **confidence:** CONDITIONAL
- **Subject:** `policy:public.comments:comments_delete_any`
- **What happened:** Permissive DELETE policy "comments_delete_any" on public.comments is constant TRUE and applies to app_user.
- **Why it matters:** Permissive policies are OR-ed: one constant-TRUE policy cancels the tenant predicate of every other permissive policy for the same command.
- **Expected / observed:** rows bounded by org_id / 
  - evidence [catalog] USING true / WITH CHECK None
- **Remediation (review before applying):** Replace the constant expression with a tenant-bounded predicate, or restrict the policy to the specific role that legitimately needs broad access.
- **Limitations:** Whether the extra access is reachable depends on SQL grants and other restrictive policies; confirm with a runtime case.
- **References:** <https://www.postgresql.org/docs/current/sql-createpolicy.html> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>

### RLS-002 · Excessively broad permissive policy

- **Severity:** Medium — Constant-TRUE permissive policy reachable by roles the spec expects to be tenant-bounded; not runtime-confirmed.
- **Evidence class:** CONFIGURATION_RISK · **provenance:** CATALOG_FACT, STATIC_INFERENCE, USER_EXPECTATION · **confidence:** CONDITIONAL
- **Subject:** `policy:public.comments:comments_select_all`
- **What happened:** Permissive SELECT policy "comments_select_all" on public.comments is constant TRUE and applies to app_user.
- **Why it matters:** Permissive policies are OR-ed: one constant-TRUE policy cancels the tenant predicate of every other permissive policy for the same command.
- **Expected / observed:** rows bounded by org_id / 
  - evidence [catalog] USING true / WITH CHECK None
- **Remediation (review before applying):** Replace the constant expression with a tenant-bounded predicate, or restrict the policy to the specific role that legitimately needs broad access.
- **Limitations:** Whether the extra access is reachable depends on SQL grants and other restrictive policies; confirm with a runtime case.
- **References:** <https://www.postgresql.org/docs/current/sql-createpolicy.html> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>

### RLS-002 · Excessively broad permissive policy

- **Severity:** Medium — Constant-TRUE permissive policy reachable by roles the spec expects to be tenant-bounded; not runtime-confirmed.
- **Evidence class:** CONFIGURATION_RISK · **provenance:** CATALOG_FACT, STATIC_INFERENCE, USER_EXPECTATION · **confidence:** CONDITIONAL
- **Subject:** `policy:public.invoices:invoices_insert`
- **What happened:** Permissive INSERT policy "invoices_insert" on public.invoices is constant TRUE and applies to app_user.
- **Why it matters:** Permissive policies are OR-ed: one constant-TRUE policy cancels the tenant predicate of every other permissive policy for the same command.
- **Expected / observed:** rows bounded by org_id / 
  - evidence [catalog] USING None / WITH CHECK true
- **Remediation (review before applying):** Replace the constant expression with a tenant-bounded predicate, or restrict the policy to the specific role that legitimately needs broad access.
- **Limitations:** Whether the extra access is reachable depends on SQL grants and other restrictive policies; confirm with a runtime case.
- **References:** <https://www.postgresql.org/docs/current/sql-createpolicy.html> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>

### RLS-002 · Excessively broad permissive policy

- **Severity:** Medium — Constant-TRUE permissive policy reachable by roles the spec expects to be tenant-bounded; not runtime-confirmed.
- **Evidence class:** CONFIGURATION_RISK · **provenance:** CATALOG_FACT, STATIC_INFERENCE, USER_EXPECTATION · **confidence:** CONDITIONAL
- **Subject:** `policy:public.invoices:invoices_update`
- **What happened:** Permissive UPDATE policy "invoices_update" on public.invoices is constant TRUE and applies to app_user.
- **Why it matters:** Permissive policies are OR-ed: one constant-TRUE policy cancels the tenant predicate of every other permissive policy for the same command.
- **Expected / observed:** rows bounded by org_id / 
  - evidence [catalog] USING (org_id IN ( SELECT m.org_id FROM memberships m WHERE (m.user_name = CURRENT_USER))) / WITH CHECK true
- **Remediation (review before applying):** Replace the constant expression with a tenant-bounded predicate, or restrict the policy to the specific role that legitimately needs broad access.
- **Limitations:** Whether the extra access is reachable depends on SQL grants and other restrictive policies; confirm with a runtime case.
- **References:** <https://www.postgresql.org/docs/current/sql-createpolicy.html> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>

### RLS-002 · Excessively broad permissive policy

- **Severity:** Medium — Constant-TRUE permissive policy reachable by roles the spec expects to be tenant-bounded; not runtime-confirmed.
- **Evidence class:** CONFIGURATION_RISK · **provenance:** CATALOG_FACT, STATIC_INFERENCE, USER_EXPECTATION · **confidence:** CONDITIONAL
- **Subject:** `policy:public.projects:projects_public_read`
- **What happened:** Permissive SELECT policy "projects_public_read" on public.projects is constant TRUE and applies to PUBLIC.
- **Why it matters:** Permissive policies are OR-ed: one constant-TRUE policy cancels the tenant predicate of every other permissive policy for the same command.
- **Expected / observed:** rows bounded by org_id / 
  - evidence [catalog] USING true / WITH CHECK None
- **Remediation (review before applying):** Replace the constant expression with a tenant-bounded predicate, or restrict the policy to the specific role that legitimately needs broad access.
- **Limitations:** Whether the extra access is reachable depends on SQL grants and other restrictive policies; confirm with a runtime case.
- **References:** <https://www.postgresql.org/docs/current/sql-createpolicy.html> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>

### RLS-002 · Excessively broad permissive policy

- **Severity:** Medium — Constant-TRUE permissive policy reachable by roles the spec expects to be tenant-bounded; not runtime-confirmed.
- **Evidence class:** CONFIGURATION_RISK · **provenance:** CATALOG_FACT, STATIC_INFERENCE, USER_EXPECTATION · **confidence:** CONDITIONAL
- **Subject:** `policy:public.projects:projects_update_loose`
- **What happened:** Permissive UPDATE policy "projects_update_loose" on public.projects is constant TRUE and applies to app_user.
- **Why it matters:** Permissive policies are OR-ed: one constant-TRUE policy cancels the tenant predicate of every other permissive policy for the same command.
- **Expected / observed:** rows bounded by org_id / 
  - evidence [catalog] USING (org_id IN ( SELECT m.org_id FROM memberships m WHERE (m.user_name = CURRENT_USER))) / WITH CHECK true
- **Remediation (review before applying):** Replace the constant expression with a tenant-bounded predicate, or restrict the policy to the specific role that legitimately needs broad access.
- **Limitations:** Whether the extra access is reachable depends on SQL grants and other restrictive policies; confirm with a runtime case.
- **References:** <https://www.postgresql.org/docs/current/sql-createpolicy.html> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>

### RLS-003 · Unintended PUBLIC role policy or grant

- **Severity:** Medium — Permissive policy with a constant-TRUE filter targets PUBLIC (every role) on a protected table.
- **Evidence class:** CONFIGURATION_RISK · **provenance:** CATALOG_FACT, STATIC_INFERENCE · **confidence:** ESTABLISHED
- **Subject:** `policy:public.projects:projects_public_read`
- **What happened:** Permissive SELECT policy "projects_public_read" on public.projects applies to PUBLIC (all roles).
- **Why it matters:** PUBLIC includes every role that exists now or is created later, including low-privilege and anonymous roles.
  - evidence [catalog] polroles = {0}
- **Remediation (review before applying):** Target an explicit role (TO app_user) instead of PUBLIC and REVOKE ... FROM PUBLIC.
- **References:** <https://www.postgresql.org/docs/current/sql-createpolicy.html> · <https://www.postgresql.org/docs/current/sql-grant.html>

### RLS-005 · INSERT / UPDATE missing or ineffective new-row guard

- **Severity:** Medium — Static: the new-row guard is absent or ineffective by expression. Other policies (for example the SELECT policy) may still block the write at runtime.
- **Evidence class:** CONFIGURATION_RISK · **provenance:** CATALOG_FACT, STATIC_INFERENCE · **confidence:** CONDITIONAL
- **Subject:** `policy:public.invoices:invoices_insert`
- **What happened:** INSERT policy "invoices_insert" on public.invoices: INSERT WITH CHECK is constant TRUE: any permitted role may insert rows for any tenant.
- **Why it matters:** WITH CHECK validates the proposed new row; without a tenant-bound check rows can be created in, or moved to, other tenants.
  - evidence [catalog] WITH CHECK true
- **Remediation (review before applying):** Add or tighten WITH CHECK so the new row satisfies the same tenant predicate as USING.
- **Limitations:** Runtime behaviour also depends on SELECT policies (PostgreSQL re-checks visibility of updated rows) - use the lab to confirm.
- **References:** <https://www.postgresql.org/docs/current/sql-createpolicy.html>

### RLS-005 · INSERT / UPDATE missing or ineffective new-row guard

- **Severity:** Medium — Static: the new-row guard is absent or ineffective by expression. Other policies (for example the SELECT policy) may still block the write at runtime.
- **Evidence class:** CONFIGURATION_RISK · **provenance:** CATALOG_FACT, STATIC_INFERENCE · **confidence:** CONDITIONAL
- **Subject:** `policy:public.invoices:invoices_update`
- **What happened:** UPDATE policy "invoices_update" on public.invoices: UPDATE WITH CHECK is constant TRUE while USING is restrictive: a role can update a visible row into another tenant.
- **Why it matters:** WITH CHECK validates the proposed new row; without a tenant-bound check rows can be created in, or moved to, other tenants.
  - evidence [catalog] WITH CHECK true
- **Remediation (review before applying):** Add or tighten WITH CHECK so the new row satisfies the same tenant predicate as USING.
- **Limitations:** Runtime behaviour also depends on SELECT policies (PostgreSQL re-checks visibility of updated rows) - use the lab to confirm.
- **References:** <https://www.postgresql.org/docs/current/sql-createpolicy.html>

### RLS-005 · INSERT / UPDATE missing or ineffective new-row guard

- **Severity:** Medium — Static: the new-row guard is absent or ineffective by expression. Other policies (for example the SELECT policy) may still block the write at runtime.
- **Evidence class:** CONFIGURATION_RISK · **provenance:** CATALOG_FACT, STATIC_INFERENCE · **confidence:** CONDITIONAL
- **Subject:** `policy:public.projects:projects_update_loose`
- **What happened:** UPDATE policy "projects_update_loose" on public.projects: UPDATE WITH CHECK is constant TRUE while USING is restrictive: a role can update a visible row into another tenant.
- **Why it matters:** WITH CHECK validates the proposed new row; without a tenant-bound check rows can be created in, or moved to, other tenants.
  - evidence [catalog] WITH CHECK true
- **Remediation (review before applying):** Add or tighten WITH CHECK so the new row satisfies the same tenant predicate as USING.
- **Limitations:** Runtime behaviour also depends on SELECT policies (PostgreSQL re-checks visibility of updated rows) - use the lab to confirm.
- **References:** <https://www.postgresql.org/docs/current/sql-createpolicy.html>

### RLS-008 · Privileged view exposure with owner-policy context

- **Severity:** Medium — View runs with its owner's rights and the owner bypasses RLS on the base table; roles can read the view. Not runtime-confirmed.
- **Evidence class:** CONFIGURATION_RISK · **provenance:** CATALOG_FACT, STATIC_INFERENCE · **confidence:** CONDITIONAL
- **Subject:** `public.v_invoices_owner`
- **What happened:** View public.v_invoices_owner (owner app_owner, no security_invoker) reads public.invoices, and its owner bypasses RLS there (TABLE_OWNER).
- **Why it matters:** Row policies on the base table are evaluated for the view owner, not for the caller, so the view can return every tenant's rows.
  - evidence [catalog] reloptions has no security_invoker
  - evidence [catalog] base table, owner bypass: TABLE_OWNER
- **Remediation (review before applying):** ALTER VIEW public.v_invoices_owner SET (security_invoker = true);
- **Limitations:** The view may filter rows itself (WHERE tenant = ...); only a runtime case can show actual leakage.
- **References:** <https://www.postgresql.org/docs/current/sql-createview.html> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>

### RLS-010 · Unexpected GRANT or column privilege

- **Severity:** Medium — Catalog-verified privilege that the spec explicitly denies.
- **Evidence class:** CONFIGURATION_RISK · **provenance:** CATALOG_FACT, USER_EXPECTATION · **confidence:** ESTABLISHED
- **Subject:** `app_user@public.comments`
- **What happened:** Role app_user holds unexpected privilege(s) TRUNCATE on public.comments.
- **Why it matters:** SQL privileges are the first gate; privileges the design does not need widen what RLS alone must contain.
- **Expected / observed:** deny TRUNCATE, REFERENCES, TRIGGER / effective DELETE, INSERT, SELECT, TRUNCATE, UPDATE
  - evidence [spec] expectation
  - evidence [catalog] TRUNCATE
- **Remediation (review before applying):** REVOKE TRUNCATE ON public.comments FROM app_user;
- **References:** <https://www.postgresql.org/docs/current/sql-grant.html>

### RLS-014 · TRUNCATE / REFERENCES / TRIGGER grant outside RLS

- **Severity:** Medium — Catalog-verified TRUNCATE grant to a non-owner role on a protected table; independent of RLS.
- **Evidence class:** CONFIGURATION_RISK · **provenance:** CATALOG_FACT · **confidence:** ESTABLISHED
- **Subject:** `public.comments:TRUNCATE`
- **What happened:** TRUNCATE on public.comments is granted to app_user.
- **Why it matters:** TRUNCATE removes every row of the table in one statement and is not subject to row policies.
  - evidence [catalog] TRUNCATE -&gt; app_user
- **Remediation (review before applying):** REVOKE TRUNCATE ON public.comments FROM app_user;
- **Limitations:** This is a privilege finding, not an RLS bypass.
- **References:** <https://www.postgresql.org/docs/current/sql-grant.html> · <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>

### RLS-009 · SECURITY DEFINER misuse candidate

- **Severity:** Needs triage — Candidate only: SECURITY DEFINER + owner bypasses RLS + callable by other roles. Function bodies are not analysed, so leakage is unproven. search_path is NOT pinned.
- **Evidence class:** CONFIGURATION_RISK · **provenance:** CATALOG_FACT, STATIC_INFERENCE · **confidence:** CONDITIONAL
- **Subject:** `public.get_invoice(p_id uuid)`
- **What happened:** SECURITY DEFINER function public.get_invoice(p_id uuid) (owner app_owner) can be executed by app_alice, app_anon, app_bob, app_charlie, app_support, app_user… and PUBLIC; its owner bypasses RLS on protected tables.
- **Why it matters:** The function body runs with the owner's rights; if it reads tenant tables without checking the caller, RLS is bypassed through the function. Without a fixed search_path, object resolution is also hijackable.
  - evidence [catalog] prosecdef = true
  - evidence [catalog] EXECUTE: PUBLIC
- **Remediation (review before applying):** Prefer SECURITY INVOKER. If DEFINER is required: ALTER FUNCTION public.get_invoice(p_id uuid) SET search_path = pg_catalog, public; REVOKE EXECUTE ON FUNCTION public.get_invoice(p_id uuid) FROM PUBLIC; and check the caller's tenant inside the body.
- **Limitations:** Not all SECURITY DEFINER functions are vulnerable. Add an EXECUTE expectation to confirm behaviour at runtime.
- **References:** <https://www.postgresql.org/docs/current/sql-createfunction.html>

### RLS-020 · Uncovered tenant table / operation

- **Severity:** Informational — Coverage gap: the boundary for these operations is unverified. This is not a vulnerability by itself.
- **Evidence class:** INCONCLUSIVE · **provenance:** USER_EXPECTATION · **confidence:** ASSUMED
- **Subject:** `public.comments`
- **What happened:** No expectation covers INSERT on public.comments.
  - evidence [spec] no expectation
- **Remediation (review before applying):** Add ALLOW and DENY expectations (own tenant / other tenant) for the missing operations.
- **References:** <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>

### RLS-020 · Uncovered tenant table / operation

- **Severity:** Informational — Coverage gap: the boundary for these operations is unverified. This is not a vulnerability by itself.
- **Evidence class:** INCONCLUSIVE · **provenance:** USER_EXPECTATION · **confidence:** ASSUMED
- **Subject:** `public.documents`
- **What happened:** No expectation covers UPDATE on public.documents.
  - evidence [spec] no expectation
- **Remediation (review before applying):** Add ALLOW and DENY expectations (own tenant / other tenant) for the missing operations.
- **References:** <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>

### RLS-020 · Uncovered tenant table / operation

- **Severity:** Informational — Coverage gap: the boundary for these operations is unverified. This is not a vulnerability by itself.
- **Evidence class:** INCONCLUSIVE · **provenance:** USER_EXPECTATION · **confidence:** ASSUMED
- **Subject:** `public.memberships`
- **What happened:** No expectation covers INSERT, UPDATE, DELETE on public.memberships.
  - evidence [spec] no expectation
- **Remediation (review before applying):** Add ALLOW and DENY expectations (own tenant / other tenant) for the missing operations.
- **References:** <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>

### RLS-020 · Uncovered tenant table / operation

- **Severity:** Informational — Coverage gap: the boundary for these operations is unverified. This is not a vulnerability by itself.
- **Evidence class:** INCONCLUSIVE · **provenance:** USER_EXPECTATION · **confidence:** ASSUMED
- **Subject:** `public.projects`
- **What happened:** No expectation covers INSERT, DELETE on public.projects.
  - evidence [spec] no expectation
- **Remediation (review before applying):** Add ALLOW and DENY expectations (own tenant / other tenant) for the missing operations.
- **References:** <https://www.postgresql.org/docs/current/ddl-rowsecurity.html>

## Test cases

| Case | Actor | Operation | Expected | Observed | Gate | Status |
|---|---|---|---|---|---|---|
| alice-reads-own-invoice | alice | SELECT | ALLOW | ROW_RETURNED | NONE | **PASS** |
| charlie-reads-colleague-invoice | charlie | SELECT | ALLOW | ROW_RETURNED | NONE | **PASS** |
| bob-reads-own-invoice | bob | SELECT | ALLOW | ROW_RETURNED | NONE | **PASS** |
| bob-cannot-read-alpha-invoice | bob | SELECT | DENY | NO_ROWS | RLS | **PASS** |
| alice-cannot-read-beta-invoice | alice | SELECT | DENY | NO_ROWS | RLS | **PASS** |
| alice-updates-own-invoice | alice | UPDATE | ALLOW | ROWS_AFFECTED | NONE | **PASS** |
| bob-cannot-update-alpha-invoice | bob | UPDATE | DENY | NO_ROWS | RLS | **PASS** |
| alice-deletes-own-invoice | alice | DELETE | ALLOW | ROWS_AFFECTED | NONE | **PASS** |
| bob-cannot-delete-alpha-invoice | bob | DELETE | DENY | NO_ROWS | RLS | **PASS** |
| bob-inserts-invoice-into-beta | bob | INSERT | ALLOW | ROW_INSERTED | NONE | **PASS** |
| bob-cannot-insert-invoice-into-alpha | bob | INSERT | DENY | ROW_INSERTED | NONE | **FAIL** |
| bob-cannot-move-own-invoice-to-alpha | bob | UPDATE | DENY | RLS_VIOLATION | RLS | **PASS** |
| bob-cannot-move-own-project-to-alpha | bob | UPDATE | DENY | ROWS_AFFECTED | NONE | **FAIL** |
| alice-upserts-own-invoice | alice | UPSERT | ALLOW | ROWS_AFFECTED | NONE | **PASS** |
| bob-cannot-upsert-over-alpha-invoice | bob | UPSERT | DENY | RLS_VIOLATION | RLS | **PASS** |
| alice-reads-amount-column | alice | SELECT | ALLOW | ROW_RETURNED | NONE | **PASS** |
| alice-cannot-read-internal-note | alice | SELECT | DENY | GRANT_DENIED | GRANT | **PASS** |
| support-reads-beta-invoice | support | SELECT | ALLOW | ROW_RETURNED | NONE | **PASS** |
| support-reads-internal-note | support | SELECT | ALLOW | ROW_RETURNED | NONE | **PASS** |
| support-cannot-delete-beta-invoice | support | DELETE | DENY | GRANT_DENIED | GRANT | **PASS** |
| support-cannot-update-alpha-invoice | support | UPDATE | DENY | GRANT_DENIED | GRANT | **PASS** |
| anon-cannot-read-invoice | anon | SELECT | DENY | GRANT_DENIED | GRANT | **PASS** |
| alice-reads-invoice-via-owner-view | alice | SELECT | ALLOW | ROW_RETURNED | NONE | **PASS** |
| bob-cannot-read-alpha-invoice-via-owner-view | bob | SELECT | DENY | ROW_RETURNED | NONE | **FAIL** |
| alice-reads-invoice-via-invoker-view | alice | SELECT | ALLOW | ROW_RETURNED | NONE | **PASS** |
| bob-cannot-read-alpha-invoice-via-invoker-view | bob | SELECT | DENY | NO_ROWS | RLS | **PASS** |
| alice-reads-invoice-via-function | alice | EXECUTE | ALLOW | ROW_RETURNED | NONE | **PASS** |
| bob-cannot-read-alpha-invoice-via-function | bob | EXECUTE | DENY | ROW_RETURNED | NONE | **FAIL** |
| alice-reads-own-comment | alice | SELECT | ALLOW | ROW_RETURNED | NONE | **PASS** |
| bob-cannot-read-alpha-comment | bob | SELECT | DENY | ROW_RETURNED | NONE | **FAIL** |
| bob-cannot-update-alpha-comment | bob | UPDATE | DENY | NO_ROWS | RLS | **PASS** |
| bob-cannot-delete-alpha-comment | bob | DELETE | DENY | ROWS_AFFECTED | NONE | **FAIL** |
| alice-reads-alpha-project | alice | SELECT | ALLOW | ROW_RETURNED | NONE | **PASS** |
| bob-cannot-read-alpha-project | bob | SELECT | DENY | ROW_RETURNED | NONE | **FAIL** |
| anon-reads-public-project | anon | SELECT | ALLOW | ROW_RETURNED | NONE | **PASS** |
| anon-cannot-read-private-project | anon | SELECT | DENY | ROW_RETURNED | NONE | **FAIL** |
| alice-reads-own-document | alice | SELECT | ALLOW | ROW_RETURNED | NONE | **PASS** |
| bob-cannot-read-alpha-document | bob | SELECT | DENY | NO_ROWS | RLS | **PASS** |
| alice-cannot-delete-own-document | alice | DELETE | DENY | NO_ROWS | RLS | **PASS** |
| alice-cannot-insert-document | alice | INSERT | DENY | RLS_VIOLATION | RLS | **PASS** |
| alice-reads-own-membership | alice | SELECT | ALLOW | ROW_RETURNED | NONE | **PASS** |
| bob-cannot-read-alice-membership | bob | SELECT | DENY | NO_ROWS | RLS | **PASS** |

## Limitations

- Results describe the tested schema in a disposable database with synthetic data; they are not proof that a production system is safe or unsafe.
- Static findings are hypotheses derived from catalog metadata; only findings marked RUNTIME_OBSERVATION were demonstrated by executing statements.
- Synthetic claim injection (supabase_synthetic) exercises policy logic only and never verifies application authentication.
- Unknown, inconclusive, skipped and unsupported cases are reported separately and never counted as verified.
- This report does not replace network controls, authentication, application authorization review or formal penetration testing.
