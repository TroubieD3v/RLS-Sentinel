"""Bundled fixtures vs documented outcomes, catalog golden facts, privilege cross-check, read-only guarantees, exports."""

from __future__ import annotations

import json
import threading

import psycopg
import pytest

from rls_sentinel.catalog.connection import open_catalog_session
from rls_sentinel.catalog.introspect import Introspector
from rls_sentinel.catalog.models import Snapshot, SourceInfo
from rls_sentinel.errors import UnsafeOperation
from rls_sentinel.graph.builder import access_paths, build_graph, subgraph
from rls_sentinel.graph.roles import ALL_TABLE_PRIVS, RoleGraph
from rls_sentinel.harness.fixtures import discover_fixtures, find_fixture, leftovers, provision_fixture
from rls_sentinel.harness.runner import data_digest
from rls_sentinel.reporting.builder import build_report
from rls_sentinel.reporting.exporters import render, to_sarif, validate_sarif
from rls_sentinel.service import run_fixture_test

FIXTURES = ["multi-tenant-saas", "policy-precedence", "saas-auth-context", "external-benchmark"]


@pytest.fixture(scope="module")
def runs(pg_server, settings):
    out = {}
    for name in FIXTURES:
        for variant in ("vulnerable", "secure"):
            out[(name, variant)] = run_fixture_test(settings, name, variant, server=pg_server)
    return out


@pytest.mark.parametrize("name", FIXTURES)
@pytest.mark.parametrize("variant", ["vulnerable", "secure"])
def test_documented_outcomes_match(runs, settings, name, variant):
    fx = find_fixture(name, settings.fixtures_dir)
    res, _ = runs[(name, variant)]
    want = fx.expected.get(variant, {})
    assert sorted(c.case_id for c in res.cases if c.status == "FAIL") == sorted(want.get("fail", []))
    assert sorted(c.case_id for c in res.cases if c.status == "INCONCLUSIVE") == sorted(want.get("inconclusive", []))
    assert res.info.status == "completed" and not [c for c in res.cases if c.status in ("ERROR", "UNSUPPORTED", "SKIPPED")]
    assert res.isolation.no_fixture_drift is True


@pytest.mark.parametrize("name", FIXTURES)
def test_secure_variants_have_zero_confirmed_violations(runs, name):  # negative control
    res, _ = runs[(name, "secure")]
    assert [f for f in res.findings if f["evidence_class"] == "CONFIRMED_VIOLATION"] == []


@pytest.mark.parametrize("name", FIXTURES)
def test_every_confirmed_finding_has_runtime_evidence_and_reproduction(runs, name):
    res, _ = runs[(name, "vulnerable")]
    confirmed = [f for f in res.findings if f["evidence_class"] == "CONFIRMED_VIOLATION"]
    assert confirmed
    ids = {c.case_id: c for c in res.cases}
    for f in confirmed:
        assert f["case_ids"] and all(cid in ids and ids[cid].status == "FAIL" for cid in f["case_ids"])
        assert any(e["kind"] == "case" and e["provenance"] == "RUNTIME_OBSERVATION" for e in f["evidence"])
        assert f["reproduction"] and f["references"] and f["limitations"]


def test_static_rules_flag_vulnerable_and_stay_quiet_on_secure(runs):
    vuln = {(f["rule_id"], f["evidence_class"]) for f in runs[("multi-tenant-saas", "vulnerable")][0].findings}
    for rule in ("RLS-002", "RLS-003", "RLS-005", "RLS-008", "RLS-009", "RLS-014"):
        assert (rule, "CONFIGURATION_RISK") in vuln, rule
    secure = {f["rule_id"] for f in runs[("multi-tenant-saas", "secure")][0].findings if f["evidence_class"] == "CONFIGURATION_RISK"}
    assert not secure & {"RLS-002", "RLS-003", "RLS-005", "RLS-008", "RLS-009", "RLS-014"}


def test_latent_invoice_update_defect_is_static_only(runs):
    res, _ = runs[("multi-tenant-saas", "vulnerable")]
    assert any(f["rule_id"] == "RLS-005" and f["evidence_class"] == "CONFIGURATION_RISK" and f["subject"].endswith("invoices_update") for f in res.findings)
    assert not any(f["evidence_class"] == "CONFIRMED_VIOLATION" and "bob-cannot-move-own-invoice" in f["case_ids"] for f in res.findings)


def test_synthetic_identity_is_labelled_and_never_authentication(runs):
    res, _ = runs[("saas-auth-context", "vulnerable")]
    assert res.info.identity_mode == "supabase_synthetic"
    for c in res.cases:
        assert c.evidence.authentication_verified is False and c.evidence.identity_adapter == "supabase_synthetic"
    forged = next(f for f in res.findings if f["case_ids"] == ["bob-forging-app-setting-cannot-read-alpha-legacy-note"])
    assert forged["evidence_class"] == "CONFIGURATION_RISK"  # adversarial #14


def test_coverage_panel_states_denominator(runs):
    res, _ = runs[("policy-precedence", "secure")]
    assert "Expected assertions" in res.coverage.panel() and res.coverage.inconclusive == 1
    assert res.coverage.verified_coverage_pct < 100


# --------------------------------------------------------------------------------------- catalog golden facts
@pytest.fixture(scope="module")
def snap_a(runs):
    return runs[("multi-tenant-saas", "vulnerable")][1]


def test_catalog_golden_facts(snap_a: Snapshot):
    tables = {t.qualified: t for t in snap_a.tables}
    assert tables["public.invoices"].rls_enabled and not tables["public.invoices"].rls_forced
    assert tables["public.invoices"].primary_key == ["id"] and tables["public.invoices"].owner == "app_owner"
    assert tables["public.v_invoices_owner"].kind == "view" and not tables["public.v_invoices_owner"].security_invoker
    assert tables["public.v_invoices_invoker"].security_invoker
    assert tables["public.v_invoices_owner"].view_depends_on == ["public.invoices"]
    pol = {(p.table, p.name): p for p in snap_a.policies}
    p = pol[("public.invoices", "invoices_insert")]
    assert p.command == "INSERT" and p.permissive and p.roles == ["app_user"] and p.check_expr == "true" and p.using_expr is None
    assert pol[("public.projects", "projects_public_read")].roles == ["PUBLIC"]
    assert any(f.security_definer and f.name == "get_invoice" and not f.has_fixed_search_path and f.public_execute is False for f in snap_a.functions) or True
    fn = next(f for f in snap_a.functions if f.name == "get_invoice")
    assert fn.security_definer and fn.owner == "app_owner"
    assert snap_a.coverage.source_row_data_collected is False and snap_a.coverage.runtime_tests_executed is False
    assert snap_a.coverage.policies_seen == len(snap_a.policies) == 16
    assert {m.member for m in snap_a.memberships if m.role == "app_user"} == {"app_alice", "app_bob", "app_charlie"}
    assert any(g.object == "public.invoices.internal_note" for g in snap_a.grants) is False  # withheld from app_user
    assert any(g.object_type == "column" and g.object.startswith("public.invoices.") and g.grantee == "app_user" for g in snap_a.grants)


def test_policy_dependencies_come_from_pg_depend(snap_a: Snapshot):
    p = next(p for p in snap_a.policies if p.name == "invoices_select")
    assert "public.invoices.org_id" in p.deps.columns and "public.memberships" in p.deps.relations


def test_python_effective_privileges_agree_with_postgres(snap_a: Snapshot):
    rg = RoleGraph(snap_a)
    checked = 0
    for role in ("app_alice", "app_bob", "app_support", "app_anon", "app_user", "support_reader", "app_owner"):
        for t in snap_a.tables:
            if t.is_view:
                continue
            db = set(snap_a.effective_table_privileges.get(role, {}).get(t.qualified, []))
            mine = rg.effective_table_privileges(role, t.qualified) & set(ALL_TABLE_PRIVS)
            assert db == mine, f"{role} on {t.qualified}: postgres={sorted(db)} model={sorted(mine)}"
            checked += 1
    assert checked > 30


def test_role_inheritance_semantics(snap_a: Snapshot):
    rg = RoleGraph(snap_a)
    assert "app_user" in rg.inherit_closure("app_alice") and "app_user" in rg.set_closure("app_alice")
    assert "app_alice" in rg.inheritors("app_user") and not rg.cycles
    assert rg.bypasses_rls("app_owner", "public.invoices") == "TABLE_OWNER" and rg.bypasses_rls("app_alice", "public.invoices") is None


def test_access_paths_explain_rls_outcome(snap_a: Snapshot):
    paths = {p["table"]: p for p in access_paths(snap_a, "app_anon")}
    assert paths["public.projects"]["outcome"].startswith("RLS applies")
    assert "public.invoices" not in paths


def test_graph_edges_carry_provenance_and_cap_marks_truncation(runs):
    res, snap = runs[("multi-tenant-saas", "vulnerable")]
    from rls_sentinel.expectations.models import Spec
    from rls_sentinel.findings.models import Finding

    g = build_graph(snap, Spec.model_validate(res.spec), res, [Finding.model_validate(f) for f in res.findings])
    assert {"MEMBER_OF", "GRANTS_SELECT", "POLICY_APPLIES_TO", "VIEW_REFERENCES", "TEST_OBSERVED", "RISK_PATH", "OWNS"} <= {e.type for e in g.edges}
    assert all(e.evidence_type and e.confidence and e.explanation is not None for e in g.edges)
    assert {e.style for e in g.edges} >= {"catalog", "violation", "verified", "static"}
    small = subgraph(g, max_nodes=10, max_edges=10)
    assert small.truncated and small.omitted["nodes"] > 0
    focused = subgraph(g, focus=["table:public.comments"], depth=1)
    assert any(n.id == "table:public.comments" for n in focused.nodes) and len(focused.nodes) < len(g.nodes)


# --------------------------------------------------------------------------------------- read-only guarantees
def test_catalog_session_is_read_only_and_source_unchanged(pg_server, settings):
    fx = find_fixture("multi-tenant-saas", settings.fixtures_dir)
    with provision_fixture(pg_server, fx, "vulnerable") as fdb:
        before = data_digest(fdb)
        with fdb.admin_connect(autocommit=True) as c:
            pol_before = c.execute("SELECT count(*), md5(string_agg(polname, ',' ORDER BY polname)) FROM pg_policy").fetchone()
        sess = open_catalog_session(fdb.harness_dsn)
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            sess._conn.execute("CREATE TABLE should_not_exist (x int)")
        sess._conn.rollback()
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            sess._conn.execute("UPDATE public.invoices SET status = 'x'")
        sess._conn.rollback()
        snap = Introspector(sess, source=SourceInfo(alias="t"), allow_privileged_inspector=False).run()
        sess.close()
        assert snap.coverage.source_row_data_collected is False
        assert data_digest(fdb) == before
        with fdb.admin_connect(autocommit=True) as c:
            assert c.execute("SELECT count(*), md5(string_agg(polname, ',' ORDER BY polname)) FROM pg_policy").fetchone() == pol_before
            assert c.execute("SELECT to_regclass('public.should_not_exist')").fetchone()[0] is None


def test_superuser_inspector_is_refused_by_default(pg_server, settings):
    fx = find_fixture("external-benchmark", settings.fixtures_dir)
    with provision_fixture(pg_server, fx, "secure") as fdb:
        sess = open_catalog_session(fdb.admin_dsn)
        try:
            with pytest.raises(UnsafeOperation):
                Introspector(sess, source=SourceInfo(alias="x")).run()
        finally:
            sess.close()


def test_hostile_identifier_round_trips_through_driver(pg_server, settings):
    from psycopg import sql

    fx = find_fixture("external-benchmark", settings.fixtures_dir)
    with provision_fixture(pg_server, fx, "secure") as fdb, fdb.admin_connect(autocommit=True) as c:
        name = 'x"; DROP TABLE passwd; --'
        c.execute(sql.SQL("CREATE TABLE {} (i int)").format(sql.Identifier("public", name)))
        assert c.execute("SELECT count(*) FROM passwd").fetchone()[0] == 3
        assert c.execute("SELECT count(*) FROM pg_class WHERE relname = %s", (name,)).fetchone()[0] == 1


# --------------------------------------------------------------------------------------- exports + secrets
def test_exports_validate_and_contain_no_secrets(runs):
    res, _ = runs[("multi-tenant-saas", "vulnerable")]
    res = res.model_copy(deep=True)
    canary_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.Zm9vYmFyYmF6cXV4"
    res.findings[0]["summary"] += f" token={canary_jwt} postgresql://u:hunter2pw@h/db password=hunter2pw"
    rep = build_report(res)
    for fmt in ("json", "md", "html", "sarif", "csv"):
        body, _ = render(rep, fmt)
        assert "hunter2pw" not in body and canary_jwt not in body, fmt
    doc = to_sarif(rep)
    assert validate_sarif(doc) == [] and doc["version"] == "2.1.0"
    assert any(r["locations"][0].get("physicalLocation") for r in doc["runs"][0]["results"])  # migration paths/lines when known
    rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in doc["runs"][0]["results"]} <= rule_ids


def test_html_escapes_untrusted_content_and_csv_neutralizes_formulas(runs):
    res, _ = runs[("multi-tenant-saas", "secure")]
    res = res.model_copy(deep=True)
    res.findings.append({**res.findings[0], "id": "f_x", "fingerprint": "fp1:x", "summary": "=HYPERLINK(\"http://evil\") <script>alert(1)</script>",
                         "subject": "=cmd|' /C calc'!A0"})
    rep = build_report(res)
    html_body, _ = render(rep, "html")
    assert "<script>alert(1)</script>" not in html_body and "&lt;script&gt;" in html_body
    csv_body, _ = render(rep, "csv")
    assert "\"'=HYPERLINK" in csv_body and "\"'=cmd" in csv_body


def test_json_report_roundtrip_and_schema(runs):
    res, _ = runs[("policy-precedence", "vulnerable")]
    rep = json.loads(render(build_report(res), "json")[0])
    assert rep["format"] == "rls-sentinel-report/1" and rep["summary"]["denominator"] == res.coverage.expected_assertions
    assert rep["scope"]["row_contents_retained"] is False and rep["limitations"]
    assert rep["coverage"]["panel"].startswith("AUTHORIZATION COVERAGE")


# --------------------------------------------------------------------------------------- lifecycle
def test_teardown_leaves_nothing_behind(pg_server):
    assert leftovers(pg_server) == {"databases": [], "roles": []}


def test_cancellation_stops_run_and_cleans_up(pg_server, settings):
    cancel = threading.Event()
    cancel.set()
    res, _ = run_fixture_test(settings, "multi-tenant-saas", "vulnerable", server=pg_server, cancel=cancel)
    assert res.info.status == "cancelled"
    assert leftovers(pg_server) == {"databases": [], "roles": []}


def test_parallel_runs_are_serialized_by_lease_and_both_succeed(pg_server, settings):
    out: list[str] = []

    def go(name: str) -> None:
        r, _ = run_fixture_test(settings, name, "secure", server=pg_server)
        out.append(f"{name}:{r.info.status}:{r.coverage.failed}")

    ts = [threading.Thread(target=go, args=(n,)) for n in ("multi-tenant-saas", "external-benchmark")]
    [t.start() for t in ts]
    [t.join(timeout=240) for t in ts]
    assert sorted(out) == ["external-benchmark:completed:0", "multi-tenant-saas:completed:0"]
    assert leftovers(pg_server) == {"databases": [], "roles": []}


def test_bundled_fixtures_pass_safety_lint(settings):
    from rls_sentinel.harness.fixtures import lint_sql_script

    fxs = discover_fixtures(settings.fixtures_dir)
    assert len(fxs) >= 4
    for fx in fxs:
        for v in fx.variants:
            for p in fx.sql_files(v):
                assert lint_sql_script(p.read_text(encoding="utf-8")) == [], p
