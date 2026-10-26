"""Unit tests: redaction, network guard, identifiers, expression analysis, spec loading, SQL generation, classification."""

from __future__ import annotations

import contextlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pglast import ast, parse_sql

from rls_sentinel.auth.netguard import resolve_allowed
from rls_sentinel.catalog.exprs import analyze_expression
from rls_sentinel.catalog.queries import Q
from rls_sentinel.errors import ConnectionRefusedByPolicy, SpecError
from rls_sentinel.expectations.loader import load_spec_text, parse_document
from rls_sentinel.expectations.models import Actor, Expectation, Spec
from rls_sentinel.harness.classify import classify
from rls_sentinel.harness.fixtures import lint_draft_sql, lint_sql_script
from rls_sentinel.harness.ops import build_plan
from rls_sentinel.harness.results import Baseline, RawObservation
from rls_sentinel.identifiers import parse_qualified
from rls_sentinel.redaction import MASK, redact_dsn, redact_obj, redact_sql_expression, redact_text

# ------------------------------------------------------------------------------------------- redaction


def test_dsn_password_masked():
    assert "s3cret" not in redact_dsn("postgresql://u:s3cret@h:5432/db")
    assert MASK in redact_dsn("postgresql://u:s3cret@h:5432/db")
    assert "s3cret" not in redact_dsn("host=h password=s3cret dbname=x")


def test_jwt_bearer_and_keys_masked():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk"
    txt = f"token={jwt} Authorization: Bearer abcdefghijklmnop sk_live_abcdefghijklmnop"
    out = redact_text(txt)
    assert jwt not in out and "abcdefghijklmnop" not in out


def test_redact_obj_recurses_and_masks_sensitive_keys():
    out = redact_obj({"password": "x", "nested": [{"dsn": "postgresql://a:b@c/d", "ok": "fine"}]})
    assert out["password"] == MASK and out["nested"][0]["dsn"] == MASK and out["nested"][0]["ok"] == "fine"


def test_policy_literals_keep_semantics_but_hide_secrets():
    e = redact_sql_expression("(role = 'admin') AND (key = 'ZmFrZS1zZWNyZXQtdmFsdWUtMTIzNDU2Nzg5MA==')")
    assert "'admin'" in e and "ZmFrZS1z" not in e


# ------------------------------------------------------------------------------------------- netguard


def test_loopback_allowed_by_default():
    assert resolve_allowed("localhost", 5432, ["localhost", "127.0.0.0/8", "::1"]).hostaddr in ("127.0.0.1", "::1")


def test_private_range_not_globally_allowed_but_configurable():
    with pytest.raises(ConnectionRefusedByPolicy):
        resolve_allowed("10.1.2.3", 5432, ["127.0.0.0/8"])
    assert resolve_allowed("10.1.2.3", 5432, ["10.0.0.0/8"]).hostaddr == "10.1.2.3"


def test_cloud_metadata_always_denied_even_if_cidr_allowed():
    with pytest.raises(ConnectionRefusedByPolicy):
        resolve_allowed("169.254.169.254", 80, ["169.254.0.0/16"])


# ------------------------------------------------------------------------------------------- identifiers


@pytest.mark.parametrize(("raw", "want"), [("public.invoices", ("public", "invoices")), ("invoices", ("public", "invoices")),
                                           ('"My Schema"."T.x"', ("My Schema", "T.x"))])
def test_parse_qualified(raw, want):
    assert parse_qualified(raw) == want


@pytest.mark.parametrize("bad", ["", "a.b.c", '"unterminated', "a..b"])
def test_parse_qualified_rejects(bad):
    with pytest.raises(SpecError):
        parse_qualified(bad)


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"), min_size=1, max_size=20),
       st.text(alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"), min_size=1, max_size=20))
@settings(max_examples=100, deadline=None)
def test_parse_qualified_roundtrips_quoted_identifiers(schema, name):
    q = '"{}"."{}"'.format(schema.replace('"', '""'), name.replace('"', '""'))
    assert parse_qualified(q) == (schema, name)


# ------------------------------------------------------------------------------------------- expressions


def test_const_folding_and_columns():
    assert analyze_expression("true").is_const_true
    assert analyze_expression("(1 = 1)").is_const_true
    assert analyze_expression("(1 = 2)").is_const_false
    info = analyze_expression("(org_id IN ( SELECT m.org_id FROM memberships m WHERE (m.user_name = CURRENT_USER)))")
    assert info.const_value is None and info.has_sublink and "org_id" in info.columns and "current_user" in info.identity_sources


def test_guc_keys_and_negative_filter_and_null_identity():
    info = analyze_expression("(org_id = (current_setting('app.org_id'::text))::uuid)")
    assert info.guc_keys == ["app.org_id"]
    assert analyze_expression("(NOT archived)").negative_filter
    assert not analyze_expression("(owner_id = auth.uid())").negative_filter
    assert analyze_expression("((owner_id = auth.uid()) OR (auth.uid() IS NULL))").null_identity_test


def test_unparseable_expression_is_unknown_not_guessed():
    info = analyze_expression("this is ( not sql")
    assert info.parse_error and info.const_value is None


def test_every_catalog_query_is_a_single_select():
    for name, text in Q.items():
        stmts = parse_sql(text.replace("%(schemas)s", "ARRAY['x']").replace("%(limit)s", "1").replace("%(role_limit)s", "1"))
        assert len(stmts) == 1 and isinstance(stmts[0].stmt, ast.SelectStmt), name


# ------------------------------------------------------------------------------------------- spec loading

VALID = """
version: 1
project: p
actors: [{id: a, pg_role: r_a, tenant: t1}, {id: b, pg_role: r_b, tenant: t2}]
tenants: [{id: t1, value: x}, {id: t2, value: y}]
resources: [{id: res, table: public.t, pk: {id: "1"}, tenant: t1}]
tables: [{table: public.t, tenant_column: org, touch_column: note}]
expectations:
  - {id: e1, actor: a, operation: SELECT, resource: res, expected: ALLOW}
  - {id: e2, actor: b, operation: SELECT, resource: res, expected: DENY}
"""


def test_valid_spec_loads():
    assert len(load_spec_text(VALID).expectations) == 2


@pytest.mark.parametrize(("mutation", "needle"), [
    (lambda s: s.replace("actor: b", "actor: nobody"), "Unknown actor"),
    (lambda s: s.replace("resource: res, expected: DENY", "resource: zzz, expected: DENY"), "Unknown resource"),
    (lambda s: s + "\n  - {id: e1, actor: a, operation: SELECT, resource: res, expected: ALLOW}", "Duplicate"),
    (lambda s: s.replace("expected: ALLOW", "expected: ALLOW, sql: 'DROP TABLE t'"), "Raw SQL"),
    (lambda s: s.replace("expected: DENY", "expected: ERROR_EXPECTED"), "expect_sqlstate"),
    (lambda s: s.replace("project: p", "project: p\nunknown_field: 1"), "Extra"),
])
def test_invalid_specs_rejected(mutation, needle):
    with pytest.raises(SpecError) as ei:
        load_spec_text(mutation(VALID))
    blob = ei.value.message + " ".join(i["message"] for i in ei.value.issues)
    assert needle.lower() in blob.lower()


def test_yaml_safety_limits():
    with pytest.raises(SpecError):
        parse_document("a: &x [1]\nb: *x\n")  # aliases refused
    with pytest.raises(SpecError):
        parse_document("a: 1\na: 2\n")  # duplicate keys refused
    with pytest.raises(SpecError):
        parse_document("x: " + "[" * 40 + "]" * 40)  # depth
    with pytest.raises(SpecError):
        parse_document("a: " + "x" * 300_000)  # size
    with pytest.raises(SpecError):
        parse_document("!!python/object/apply:os.system ['echo']")


@given(st.text(max_size=300))
@settings(max_examples=150, deadline=None)
def test_malformed_input_never_crashes_only_specerror(txt):
    with contextlib.suppress(SpecError):
        load_spec_text(txt)


# ------------------------------------------------------------------------------------------- SQL generation


def _spec() -> Spec:
    return load_spec_text(VALID)


def test_generated_sql_is_parameterized_and_identifiers_composed():
    spec = _spec()
    plan = build_plan(spec, spec.expectations[0], claims=None)
    text = repr(plan.statement)
    assert "%s" in text and plan.params == ["1"]
    assert "SQL('1')" in text  # the constant projection only; the key value is a bound parameter
    assert text.count("%s") == 1


def test_draft_and_fixture_lint_allow_lists():
    assert lint_draft_sql("CREATE POLICY p ON t USING (true); ALTER TABLE t ENABLE ROW LEVEL SECURITY;") == []
    for bad in ("DROP TABLE t", "COPY t TO PROGRAM 'x'", "SET ROLE postgres", "DO $$ BEGIN END $$", "CREATE EXTENSION x", "SELECT 1"):
        assert lint_draft_sql(bad), bad
    assert lint_sql_script("COPY t FROM PROGRAM 'x'")
    assert lint_sql_script("CREATE FUNCTION f() RETURNS int LANGUAGE c AS 'x'")
    assert lint_sql_script("CREATE TABLE t(i int); INSERT INTO t VALUES (1);") == []


# ------------------------------------------------------------------------------------------- classification semantics


def _exp(expected: str, **kw) -> Expectation:
    base = {"id": "c", "actor": "a", "operation": "SELECT", "resource": "r", "expected": expected}
    return Expectation.model_validate(base | kw)


ACTOR = Actor(id="a", pg_role="r")
EXISTS = Baseline(target_exists=True)


def _raw(observed: str, **kw) -> RawObservation:
    return RawObservation(observed=observed, **kw)  # type: ignore[arg-type]


def test_grant_denial_is_not_scored_as_rls_success():  # adversarial #4
    v = classify(_exp("DENY"), ACTOR, _raw("GRANT_DENIED", sqlstate="42501", gate="GRANT"), EXISTS, control_status=None)
    assert v.status == "INCONCLUSIVE"
    assert classify(_exp("DENY", deny_gate="grant"), ACTOR, _raw("GRANT_DENIED", gate="GRANT"), EXISTS, control_status=None).status == "PASS"


def test_missing_baseline_is_inconclusive_not_pass():  # adversarial #5
    v = classify(_exp("DENY"), ACTOR, _raw("NO_ROWS", gate="RLS"), Baseline(target_exists=False), control_status=None)
    assert v.status == "INCONCLUSIVE"


def test_infrastructure_errors_are_never_deny_or_pass():  # adversarial #9
    for obs in ("INFRA_ERROR", "TIMEOUT"):
        assert classify(_exp("DENY"), ACTOR, _raw(obs), EXISTS, control_status=None).status == "ERROR"
        assert classify(_exp("ALLOW"), ACTOR, _raw(obs), EXISTS, control_status=None).status == "ERROR"


def test_bypass_actor_never_reported_as_policy_governed():  # adversarial #2/#3
    v = classify(_exp("ALLOW"), ACTOR, _raw("ROW_RETURNED", bypass_reason="BYPASSRLS"), EXISTS, control_status=None)
    assert v.status == "INCONCLUSIVE"
    v = classify(_exp("DENY"), ACTOR, _raw("ROW_RETURNED", bypass_reason="TABLE_OWNER"), EXISTS, control_status=None)
    assert v.status == "FAIL" and v.rule_hint == "RLS-004"
    ok = classify(_exp("ALLOW"), Actor(id="a", pg_role="r", expect_bypass=True), _raw("ROW_RETURNED", bypass_reason="BYPASSRLS"), EXISTS, control_status=None)
    assert ok.status == "PASS"


def test_failed_positive_control_makes_denial_vacuous():
    v = classify(_exp("DENY"), ACTOR, _raw("NO_ROWS", gate="RLS"), EXISTS, control_status="FAIL")
    assert v.status == "INCONCLUSIVE"


def test_zero_rows_where_rls_did_not_apply_is_not_attributed_to_rls():
    assert classify(_exp("DENY"), ACTOR, _raw("NO_ROWS", gate="NONE"), EXISTS, control_status=None).status == "INCONCLUSIVE"


def test_policy_dependency_error_is_not_a_denial():
    v = classify(_exp("DENY"), ACTOR, _raw("POLICY_DEPENDENCY_ERROR", sqlstate="42501"), EXISTS, control_status=None)
    assert v.status == "INCONCLUSIVE" and v.rule_hint == "RLS-012"


def test_constraint_error_on_write_is_inconclusive_with_ordering_note():
    v = classify(_exp("DENY", operation="INSERT", table="public.t", resource=None, row={"id": 1}), ACTOR, _raw("CONSTRAINT_ERROR", sqlstate="23503"), EXISTS, control_status=None)
    assert v.status == "INCONCLUSIVE" and "before constraints" in v.reason


def test_forged_claim_is_configuration_risk_not_confirmed_violation():  # adversarial #14 support
    exp = _exp("DENY")
    object.__setattr__(exp, "claims_override", {"sub": "x"})
    v = classify(exp, ACTOR, _raw("ROW_RETURNED"), EXISTS, control_status=None)
    assert v.status == "FAIL" and v.finding_class == "CONFIGURATION_RISK"


def test_allow_blocked_is_failure_and_error_expected_requires_sqlstate():
    assert classify(_exp("ALLOW"), ACTOR, _raw("NO_ROWS", gate="RLS"), EXISTS, control_status=None).status == "FAIL"
    e = _exp("ERROR_EXPECTED", expect_sqlstate="23505")
    assert classify(e, ACTOR, _raw("CONSTRAINT_ERROR", sqlstate="23505"), EXISTS, control_status=None).status == "PASS"
    assert classify(e, ACTOR, _raw("ROW_RETURNED"), EXISTS, control_status=None).status == "FAIL"
