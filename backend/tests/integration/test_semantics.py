"""PostgreSQL RLS semantics verified on a REAL disposable server (spec 3.1 / 21.2 adversarial acceptance checks)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from rls_sentinel.expectations.loader import load_spec_text
from rls_sentinel.harness.fixtures import load_fixture
from rls_sentinel.service import run_fixture_test

SQL = """
CREATE ROLE sem_owner NOLOGIN;
CREATE ROLE sem_u1 NOLOGIN;
CREATE ROLE sem_u2 NOLOGIN;
CREATE ROLE sem_bypass NOLOGIN BYPASSRLS;
CREATE ROLE sem_nogrant NOLOGIN;
GRANT USAGE, CREATE ON SCHEMA public TO sem_owner;
GRANT USAGE ON SCHEMA public TO sem_u1, sem_u2, sem_bypass, sem_nogrant;
SET ROLE sem_owner;

-- (1) RLS enabled, NO policy: default deny, never "open"
CREATE TABLE nopol (id int PRIMARY KEY, v text);
ALTER TABLE nopol ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON nopol TO sem_u1;

-- tenant table with a correct policy
CREATE TABLE t (id int PRIMARY KEY, tenant text NOT NULL, v text);
ALTER TABLE t ENABLE ROW LEVEL SECURITY;
CREATE POLICY t_sel ON t FOR SELECT TO sem_u1, sem_u2 USING (tenant = CASE current_user WHEN 'sem_u1' THEN 'a' ELSE 'b' END);
CREATE POLICY t_upd ON t FOR UPDATE TO sem_u1, sem_u2
    USING (tenant = CASE current_user WHEN 'sem_u1' THEN 'a' ELSE 'b' END)
    WITH CHECK (tenant = CASE current_user WHEN 'sem_u1' THEN 'a' ELSE 'b' END);
GRANT SELECT, UPDATE ON t TO sem_u1, sem_u2, sem_bypass;

-- (6) tenant-move test where nothing masks a loose WITH CHECK: SELECT policy is wide open
CREATE TABLE m (id int PRIMARY KEY, tenant text NOT NULL);
ALTER TABLE m ENABLE ROW LEVEL SECURITY;
CREATE POLICY m_sel ON m FOR SELECT TO sem_u1 USING (true);
CREATE POLICY m_upd ON m FOR UPDATE TO sem_u1 USING (tenant = 'a') WITH CHECK (true);
GRANT SELECT, UPDATE ON m TO sem_u1;

-- owner bypass (no FORCE) vs FORCE
CREATE TABLE own_open (id int PRIMARY KEY, v text);
ALTER TABLE own_open ENABLE ROW LEVEL SECURITY;
CREATE TABLE own_forced (id int PRIMARY KEY, v text);
ALTER TABLE own_forced ENABLE ROW LEVEL SECURITY;
ALTER TABLE own_forced FORCE ROW LEVEL SECURITY;

-- (8) restrictive-only policy grants nothing
CREATE TABLE restr (id int PRIMARY KEY);
ALTER TABLE restr ENABLE ROW LEVEL SECURITY;
CREATE POLICY r_only ON restr AS RESTRICTIVE FOR SELECT USING (true);
GRANT SELECT ON restr TO sem_u1;

-- (7) owner-privileged view versus security_invoker view
CREATE VIEW v_owner AS SELECT id, tenant, v FROM t;
CREATE VIEW v_invoker WITH (security_invoker = true) AS SELECT id, tenant, v FROM t;
GRANT SELECT ON v_owner, v_invoker TO sem_u2;

-- (4) grant gate: sem_nogrant has no privilege at all on t
RESET ROLE;
INSERT INTO nopol VALUES (1, 'x');
INSERT INTO t VALUES (1, 'a', 'one'), (2, 'b', 'two');
INSERT INTO m VALUES (1, 'a');
INSERT INTO own_open VALUES (1, 'x');
INSERT INTO own_forced VALUES (1, 'x');
INSERT INTO restr VALUES (1);
"""

SPEC = """
version: 1
project: semantics
identity_mode: postgres_roles
tenants: [{id: a, value: a}, {id: b, value: b}]
actors:
  - {id: u1, pg_role: sem_u1, tenant: a}
  - {id: u2, pg_role: sem_u2, tenant: b}
  - {id: owner, pg_role: sem_owner, kind: owner}
  - {id: byp, pg_role: sem_bypass}
  - {id: byp_ok, pg_role: sem_bypass, expect_bypass: true}
  - {id: nogrant, pg_role: sem_nogrant}
resources:
  - {id: nopol_row, table: public.nopol, pk: {id: 1}}
  - {id: t_a, table: public.t, pk: {id: 1}, tenant: a}
  - {id: t_b, table: public.t, pk: {id: 2}, tenant: b}
  - {id: t_missing, table: public.t, pk: {id: 999}, tenant: a}
  - {id: m_a, table: public.m, pk: {id: 1}, tenant: a}
  - {id: own_open_row, table: public.own_open, pk: {id: 1}}
  - {id: own_forced_row, table: public.own_forced, pk: {id: 1}}
  - {id: restr_row, table: public.restr, pk: {id: 1}}
tables:
  - {table: public.t, tenant_column: tenant, touch_column: v}
  - {table: public.m, tenant_column: tenant, touch_column: tenant}
  - {table: public.nopol, touch_column: v}
  - {table: public.own_open, touch_column: v}
  - {table: public.own_forced, touch_column: v}
expectations:
  - {id: control-u1-reads-t_a, actor: u1, operation: SELECT, resource: t_a, expected: ALLOW}
  - {id: u1-cannot-read-t_b, actor: u1, operation: SELECT, resource: t_b, expected: DENY}
  - {id: u1-nopol-denied, actor: u1, operation: SELECT, resource: nopol_row, expected: DENY}
  - {id: bypass-unmarked-allow, actor: byp, operation: SELECT, resource: t_b, expected: ALLOW}
  - {id: bypass-unmarked-deny, actor: byp, operation: SELECT, resource: t_b, expected: DENY}
  - {id: bypass-marked-allow, actor: byp_ok, operation: SELECT, resource: t_b, expected: ALLOW}
  - {id: owner-open-deny, actor: owner, operation: SELECT, resource: own_open_row, expected: DENY}
  - {id: owner-forced-deny, actor: owner, operation: SELECT, resource: own_forced_row, expected: DENY}
  - {id: nogrant-default-gate, actor: nogrant, operation: SELECT, resource: t_a, expected: DENY}
  - {id: nogrant-grant-gate, actor: nogrant, operation: SELECT, resource: t_a, expected: DENY, deny_gate: grant}
  - {id: u2-missing-row-deny, actor: u2, operation: SELECT, resource: t_missing, expected: DENY}
  - {id: u1-move-masked-by-select-policy, actor: u1, operation: UPDATE, resource: t_a, set_tenant: b, expected: DENY}
  - {id: u1-move-unmasked, actor: u1, operation: UPDATE, resource: m_a, set_tenant: b, expected: DENY}
  - {id: u2-via-owner-view, actor: u2, operation: SELECT, resource: t_a, via: public.v_owner, expected: DENY}
  - {id: u2-via-invoker-view, actor: u2, operation: SELECT, resource: t_a, via: public.v_invoker, expected: DENY}
  - {id: restrictive-only-denies, actor: u1, operation: SELECT, resource: restr_row, expected: DENY}
"""


@pytest.fixture(scope="module")
def results(pg_server, settings, tmp_path_factory):
    root: Path = tmp_path_factory.mktemp("semfx")
    (root / "sql").mkdir()
    (root / "specs").mkdir()
    (root / "sql" / "all.sql").write_text(SQL, encoding="utf-8")
    (root / "specs" / "s.yaml").write_text(SPEC, encoding="utf-8")
    (root / "fixture.yaml").write_text(textwrap.dedent("""
        name: semantics
        roles: [sem_owner, sem_u1, sem_u2, sem_bypass, sem_nogrant]
        variants: {secure: [sql/all.sql]}
        spec: specs/s.yaml
    """), encoding="utf-8")
    fx = load_fixture(root)
    run, _snap = run_fixture_test(settings, fx, "secure", spec=load_spec_text(SPEC), server=pg_server)
    return {c.case_id: c for c in run.cases}, run


def test_control_passes_and_isolation_proven(results):
    cases, run = results
    assert cases["control-u1-reads-t_a"].status == "PASS"
    assert run.isolation.no_fixture_drift is True and run.isolation.harness_superuser is False and run.isolation.harness_bypassrls is False
    assert run.isolation.source_database_touched is False


def test_rls_enabled_without_policy_is_default_deny_not_open(results):  # adversarial #1
    c = results[0]["u1-nopol-denied"]
    assert c.status == "PASS" and c.observed == "NO_ROWS" and c.gate == "RLS"
    assert c.evidence.raw.rls_applies and not c.evidence.raw.applicable_policies


def test_bypassrls_role_is_not_reported_as_policy_governed(results):  # adversarial #2
    cases = results[0]
    assert cases["bypass-unmarked-allow"].status == "INCONCLUSIVE"
    f = cases["bypass-unmarked-deny"]
    assert f.status == "FAIL" and f.evidence.raw.bypass_reason == "BYPASSRLS"
    assert cases["bypass-marked-allow"].status == "PASS"


def test_owner_bypass_identified_and_force_changes_it(results):  # adversarial #3
    cases = results[0]
    assert cases["owner-open-deny"].status == "FAIL" and cases["owner-open-deny"].evidence.raw.bypass_reason == "TABLE_OWNER"
    forced = cases["owner-forced-deny"]
    assert forced.status == "PASS" and forced.evidence.raw.bypass_reason is None


def test_42501_grant_denial_is_not_an_rls_success(results):  # adversarial #4
    cases = results[0]
    assert cases["nogrant-default-gate"].status == "INCONCLUSIVE" and cases["nogrant-default-gate"].gate == "GRANT"
    assert cases["nogrant-grant-gate"].status == "PASS"


def test_missing_target_row_is_inconclusive_not_pass(results):  # adversarial #5
    assert results[0]["u2-missing-row-deny"].status == "INCONCLUSIVE"


def test_tenant_change_tests_new_row_check(results):  # adversarial #6
    cases = results[0]
    # tenant-scoped SELECT policy also guards the new row, masking the loose WITH CHECK -> not a confirmed violation
    assert cases["u1-move-masked-by-select-policy"].status == "PASS"
    # nothing masks it here -> the new-row (WITH CHECK) hole is real
    assert cases["u1-move-unmasked"].status == "FAIL"


def test_owner_view_and_invoker_view_evaluated_differently(results):  # adversarial #7
    cases = results[0]
    assert cases["u2-via-owner-view"].status == "FAIL" and cases["u2-via-owner-view"].evidence.raw.bypass_reason == "VIEW_OWNER_BYPASS"
    assert cases["u2-via-invoker-view"].status == "PASS"


def test_restrictive_only_policy_does_not_grant_access(results):  # adversarial #8
    c = results[0]["restrictive-only-denies"]
    assert c.status == "PASS" and c.observed == "NO_ROWS"


def test_rule_mapping_for_confirmed_findings(results):
    run = results[1]
    by_case = {f["case_ids"][0]: f for f in run.findings if f["case_ids"]}
    assert by_case["owner-open-deny"]["rule_id"] == "RLS-004"
    assert by_case["u2-via-owner-view"]["rule_id"] == "RLS-008"
    assert by_case["u1-move-unmasked"]["rule_id"] == "RLS-005"
    assert by_case["u1-move-unmasked"]["severity"] == "Critical"
    assert all(f["evidence_class"] != "CONFIRMED_VIOLATION" or "RUNTIME_OBSERVATION" in f["provenance"] for f in run.findings)
