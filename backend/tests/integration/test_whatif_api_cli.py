"""What-if Lab, REST API and CLI behaviour end to end on real disposable PostgreSQL."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from rls_sentinel.api.app import create_app
from rls_sentinel.cli.main import app as cli_app
from rls_sentinel.errors import SpecError
from rls_sentinel.service import run_fixture_test
from rls_sentinel.whatif.lab import run_whatif

H = {"X-Sentinel-Client": "pytest"}
HOLD_FIX = """
DROP POLICY art_hold_update ON articles;
CREATE POLICY art_hold_update ON articles AS RESTRICTIVE FOR UPDATE TO PUBLIC USING (NOT legal_hold) WITH CHECK (NOT legal_hold);
DROP POLICY art_hold_delete ON articles;
CREATE POLICY art_hold_delete ON articles AS RESTRICTIVE FOR DELETE TO PUBLIC USING (NOT legal_hold);
"""


@pytest.fixture(scope="module")
def baseline(pg_server, settings):
    return run_fixture_test(settings, "policy-precedence", "vulnerable", server=pg_server)[0]


# ---------------------------------------------------------------------------------------------- What-if
def test_whatif_fix_resolves_failures_without_regressions(pg_server, settings, baseline):
    r = run_whatif(settings, "policy-precedence", "vulnerable", HOLD_FIX, baseline=baseline, server=pg_server)
    assert r.banner.startswith("SIMULATED IN DISPOSABLE DATABASE") and r.no_live_changes
    assert r.verdict == "improves" and r.summary["resolved"] >= 2 and r.summary["regression"] == 0 and r.summary["broader_access"] == 0
    resolved = {d.case_id for d in r.deltas if d.kind == "resolved"}
    assert {"editor-cannot-update-legal-hold", "editor-cannot-delete-legal-hold"} <= resolved
    assert r.snapshot_diff is not None and any(c.category == "policy" for c in r.snapshot_diff.changes)
    assert r.sandbox_run is not None and r.sandbox_run.info.environment_mode == "SANDBOX REPLAY"


def test_whatif_flags_regression_when_fix_blocks_authorized_user(pg_server, settings):
    secure = run_fixture_test(settings, "policy-precedence", "secure", server=pg_server)[0]
    r = run_whatif(settings, "policy-precedence", "secure", "DROP POLICY art_editor_update ON articles;", baseline=secure, server=pg_server)
    assert r.verdict == "regresses"
    assert any(d.case_id == "editor-updates-internal-memo" and d.kind == "regression" for d in r.deltas)


def test_whatif_flags_broader_policy(pg_server, settings):
    secure = run_fixture_test(settings, "policy-precedence", "secure", server=pg_server)[0]
    r = run_whatif(settings, "policy-precedence", "secure", "CREATE POLICY open_all ON locked FOR SELECT TO PUBLIC USING (true);", baseline=secure, server=pg_server)
    assert r.summary["broader_access"] >= 1 and r.verdict in ("regresses", "mixed")


@pytest.mark.parametrize("bad", ["DROP TABLE articles", "COPY articles TO PROGRAM 'calc'", "SET ROLE sentinel_admin", "DO $$ BEGIN PERFORM 1; END $$",
                                 "CREATE EXTENSION file_fdw", "ALTER SYSTEM SET fsync = off", "SELECT pg_read_file('/etc/passwd')"])
def test_whatif_rejects_unsafe_drafts_before_provisioning(pg_server, settings, baseline, bad):
    with pytest.raises(SpecError):
        run_whatif(settings, "policy-precedence", "vulnerable", bad, baseline=baseline, server=pg_server)


def test_whatif_apply_error_is_reported_and_rolled_back(pg_server, settings, baseline):
    r = run_whatif(settings, "policy-precedence", "vulnerable", "ALTER POLICY nope ON articles USING (true);", baseline=baseline, server=pg_server)
    assert r.verdict == "apply_failed" and r.apply_error


# ---------------------------------------------------------------------------------------------- API
@pytest.fixture(scope="module")
def client(settings, tmp_path_factory):
    settings.data_dir = tmp_path_factory.mktemp("data")
    settings.metadata_url = None
    settings.fixture_backend = "local"
    app = create_app(settings)
    with TestClient(app, base_url="http://localhost") as c:
        yield c


def _wait_run(client, rid, timeout=180):
    t = time.time()
    while time.time() - t < timeout:
        m = client.get(f"/api/v1/test-runs/{rid}").json()["data"]
        if m["status"] in ("completed", "failed", "cancelled"):
            return m
        time.sleep(0.4)
    raise AssertionError("run did not finish")


def test_api_full_journey(client):
    assert client.get("/api/v1/health").json()["data"]["status"] == "ok"
    r = client.post("/api/v1/test-runs", json={"fixture": "multi-tenant-saas", "variant": "vulnerable"}, headers=H)
    assert r.status_code == 202
    rid = r.json()["data"]["run_id"]
    m = _wait_run(client, rid)
    assert m["status"] == "completed" and m["summary"]["coverage"]["failed"] == 8
    mx = client.get(f"/api/v1/test-runs/{rid}/matrix").json()["data"]
    assert mx["totals"]["FAIL"] == 8 and mx["denominator"] == 42 and mx["executed"]
    cases = client.get(f"/api/v1/test-runs/{rid}/cases", params={"status": "FAIL"}).json()
    assert cases["meta"]["pagination"]["total"] == 8
    assert all(c["evidence"]["record_identifier_masked"] and not c["evidence"]["row_contents_retained"] for c in cases["data"])
    f = client.get("/api/v1/findings", params={"run_id": rid, "evidence_class": "CONFIRMED_VIOLATION"}).json()
    assert f["meta"]["pagination"]["total"] == 8
    fid = f["data"][0]["id"]
    assert client.get(f"/api/v1/findings/{fid}").json()["data"]["case_ids"]
    rv = client.patch(f"/api/v1/findings/{fid}", json={"lifecycle_state": "triaged", "reviewer_note": "looking"}, headers=H).json()["data"]
    assert rv["lifecycle_state"] == "triaged"
    for fmt, ctype in (("json", "application/json"), ("md", "text/markdown"), ("html", "text/html"), ("sarif", "application/sarif+json"), ("csv", "text/csv")):
        resp = client.get(f"/api/v1/reports/{rid}", params={"format": fmt})
        assert resp.status_code == 200 and resp.headers["content-type"].startswith(ctype)
    assert client.get(f"/api/v1/reports/{rid}", params={"format": "xlsx"}).status_code == 422
    assert "event: completed" in client.get(f"/api/v1/test-runs/{rid}/events").text
    g = client.get(f"/api/v1/test-runs/{rid}/graph").json()
    assert g["data"]["nodes"] and "truncated" in g["meta"]
    assert client.get(f"/api/v1/test-runs/{rid}/suggestions").json()["data"]["suggestions"]
    assert "def test_authorization_case" in client.get(f"/api/v1/test-runs/{rid}/pytest").text
    # history + diff vs. secure run
    r2 = client.post("/api/v1/test-runs", json={"fixture": "multi-tenant-saas", "variant": "secure"}, headers=H).json()["data"]["run_id"]
    _wait_run(client, r2)
    d = client.post("/api/v1/diff", json={"from_run_id": rid, "to_run_id": r2}, headers=H).json()["data"]
    assert d["diff"]["summary"]["resolved"] == 8 and d["finding_labels"]["resolved"]
    hist = client.get("/api/v1/history").json()["data"]
    assert {h["variant"] for h in hist} >= {"vulnerable", "secure"} and all("verified_coverage_pct" in h for h in hist)
    # what-if via API
    w = client.post("/api/v1/what-if", json={"run_id": rid, "draft_sql": "DROP POLICY comments_select_all ON comments;\nDROP POLICY comments_delete_any ON comments;"}, headers=H)
    wid = w.json()["data"]["id"]
    for _ in range(300):
        ww = client.get(f"/api/v1/what-if/{wid}").json()["data"]
        if ww["status"] in ("completed", "failed"):
            break
        time.sleep(0.4)
    assert ww["status"] == "completed" and ww["verdict"] == "improves" and ww["banner"].startswith("SIMULATED")
    bad = client.post("/api/v1/what-if", json={"run_id": rid, "draft_sql": "DROP TABLE comments"}, headers=H)
    assert bad.status_code == 422 and bad.headers["content-type"].startswith("application/problem+json")


def test_api_security_controls(client):
    assert client.post("/api/v1/workspaces", json={"name": "x"}).status_code == 403  # CSRF header
    assert client.post("/api/v1/workspaces", json={"name": "x"}, headers={**H, "Origin": "http://evil.example"}).status_code == 403
    assert client.get("/api/v1/health", headers={"Host": "evil.example"}).status_code == 421  # DNS-rebinding defence
    assert client.post("/api/v1/workspaces", json={"name": "ws", "unexpected": 1}, headers=H).status_code == 422
    r = client.post("/api/v1/test-runs", json={"fixture": "nope", "variant": "secure"}, headers=H)
    assert r.status_code == 404 and r.json()["code"] == "not_found"
    assert client.get("/api/v1/expectations/validate").status_code == 405


def test_api_connection_allowlist_and_secret_handling(client):
    r = client.post("/api/v1/connections/test", json={"dsn": "postgresql://u:topsecret@10.255.255.1:5432/db"}, headers=H)
    assert r.status_code == 403 and "topsecret" not in r.text  # not in SENTINEL_ALLOWED_TARGETS
    r = client.post("/api/v1/connections/test", json={"dsn": "postgresql://u:topsecret@169.254.169.254/db"}, headers=H)
    assert r.status_code == 403 and "topsecret" not in r.text
    r = client.post("/api/v1/connections/test", json={"dsn": "postgresql://u:topsecret@127.0.0.1:1/db"}, headers=H)
    assert r.status_code in (502, 503) and "topsecret" not in r.text  # unreachable is an error, never a pass


def test_api_validate_spec_and_schema(client):
    ok = client.post("/api/v1/expectations/validate", json={"spec": "version: 1\nproject: p\nactors: [{id: a, pg_role: r}]\n"}, headers=H).json()["data"]
    assert ok["valid"] and ok["checksum"].startswith("sha256:")
    bad = client.post("/api/v1/expectations/validate", json={"spec": "version: 1\nproject: p\nactors: []\n"}, headers=H).json()["data"]
    assert not bad["valid"] and bad["issues"]
    sch = client.get("/api/v1/schema/spec").json()["data"]
    assert sch["title"] == "Spec" and "expectations" in sch["properties"]


def test_suppression_lifecycle_hides_but_never_alters_results(client):
    runs = client.get("/api/v1/test-runs").json()["data"]
    rid = next(r["id"] for r in runs if r["variant"] == "vulnerable" and r["kind"] == "lab")
    before = client.get("/api/v1/findings", params={"run_id": rid, "rule_id": "RLS-014"}).json()["meta"]["pagination"]["total"]
    assert before >= 1
    exp = (datetime.now(UTC) + timedelta(days=30)).isoformat()
    assert client.post("/api/v1/suppressions", json={"rule_id": "RLS-014", "reason": "accepted until next release", "owner": "sec", "reviewer": "lead",
                                                     "expires_at": (datetime.now(UTC) - timedelta(days=1)).isoformat()}, headers=H).status_code == 422
    s = client.post("/api/v1/suppressions", json={"rule_id": "RLS-014", "reason": "accepted until next release", "owner": "sec", "reviewer": "lead", "expires_at": exp}, headers=H)
    assert s.status_code == 201
    assert client.get("/api/v1/findings", params={"run_id": rid, "rule_id": "RLS-014"}).json()["meta"]["pagination"]["total"] == 0
    shown = client.get("/api/v1/findings", params={"run_id": rid, "rule_id": "RLS-014", "include_suppressed": "true"}).json()["data"]
    assert shown and shown[0]["suppressed"] and shown[0]["suppression"]["owner"] == "sec" and shown[0]["evidence"]
    client.delete(f"/api/v1/suppressions/{s.json()['data']['id']}", headers=H)
    assert client.get("/api/v1/findings", params={"run_id": rid, "rule_id": "RLS-014"}).json()["meta"]["pagination"]["total"] == before
    types = [e["event_type"] for e in client.get("/api/v1/audit").json()["data"]]
    assert "suppression.create" in types and "suppression.revoke" in types


def test_audit_events_are_immutable(client):
    from rls_sentinel.persistence.models import AuditEvent

    db = client.app.state.ctx.db
    db.audit("tester", "x.test")
    with pytest.raises(Exception, match="immutable"), db.session() as s:
        ev = s.query(AuditEvent).first()
        ev.actor = "tamper"
        s.flush()
    with pytest.raises(Exception, match="immutable"), db.session() as s:
        s.delete(s.query(AuditEvent).first())
        s.flush()


def test_token_mode_requires_bearer_and_refuses_public_bind_without_token(settings, tmp_path):
    settings.data_dir = tmp_path
    settings.api_token = "t0ken-for-tests"
    settings.fixture_backend = "local"
    with TestClient(create_app(settings), base_url="http://localhost") as c:
        assert c.get("/api/v1/health").status_code == 200
        assert c.get("/api/v1/workspaces").status_code == 401
        assert c.get("/api/v1/workspaces", headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert c.get("/api/v1/workspaces", headers={"Authorization": "Bearer t0ken-for-tests"}).status_code == 200
    settings.api_token = None
    settings.host = "0.0.0.0"  # noqa: S104
    with pytest.raises(RuntimeError, match="non-loopback"):
        create_app(settings)
    settings.host = "127.0.0.1"


def test_retention_purge_and_delete_workflow(client):
    runs = client.get("/api/v1/test-runs").json()["data"]
    victim = runs[-1]["id"]
    assert client.delete(f"/api/v1/test-runs/{victim}", headers=H).status_code == 204
    assert client.get(f"/api/v1/test-runs/{victim}").status_code == 404
    out = client.post("/api/v1/retention/purge", json={"days": 3650}, headers=H).json()["data"]
    assert set(out) == {"runs", "snapshots", "audit_events"}


# ---------------------------------------------------------------------------------------------- CLI
runner = CliRunner()


def test_cli_exit_codes_and_files(tmp_path, settings):
    out = tmp_path / "run.json"
    r = runner.invoke(cli_app, ["test", "--fixture", "multi-tenant-saas", "--variant", "vulnerable", "-o", str(out), "-q", "--backend", "local"])
    assert r.exit_code == 1, r.output
    run = json.loads(out.read_text(encoding="utf-8"))
    assert run["format"] == "rls-sentinel-run/1" and run["coverage"]["failed"] == 8
    sarif = tmp_path / "f.sarif"
    r = runner.invoke(cli_app, ["report", str(out), "--format", "sarif", "-o", str(sarif), "--spec-uri", "fixtures/x.yaml"])
    assert r.exit_code == 0 and json.loads(sarif.read_text(encoding="utf-8"))["version"] == "2.1.0"
    sec = tmp_path / "sec.json"
    r = runner.invoke(cli_app, ["test", "--fixture", "multi-tenant-saas", "--variant", "secure", "-o", str(sec), "-q", "--backend", "local"])
    assert r.exit_code == 0, r.output
    r = runner.invoke(cli_app, ["diff", str(out), str(sec), "--fail-on-regression"])
    assert r.exit_code == 0 and "resolved" in r.output
    r = runner.invoke(cli_app, ["diff", str(sec), str(out), "--fail-on-regression"])
    assert r.exit_code == 1  # secure -> vulnerable is a regression
    gen = tmp_path / "test_gen.py"
    assert runner.invoke(cli_app, ["export-tests", str(out), "-o", str(gen)]).exit_code == 0
    assert "parametrize" in gen.read_text(encoding="utf-8")


def test_cli_inconclusive_is_never_safe(tmp_path):
    r = runner.invoke(cli_app, ["test", "--fixture", "policy-precedence", "--variant", "secure", "-q", "--backend", "local", "-o", str(tmp_path / "o.json")])
    assert r.exit_code == 3  # 1 inconclusive case, default required coverage 100%
    r = runner.invoke(cli_app, ["test", "--fixture", "policy-precedence", "--variant", "secure", "-q", "--backend", "local", "--min-coverage", "90", "-o", str(tmp_path / "o.json")])
    assert r.exit_code == 0


def test_cli_usage_errors_exit_2(tmp_path):
    assert runner.invoke(cli_app, ["test", "--fixture", "nope"]).exit_code == 2
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nproject: x\nactors: []\n", encoding="utf-8")
    assert runner.invoke(cli_app, ["spec", "validate", str(bad)]).exit_code == 2
    assert runner.invoke(cli_app, ["scan", "--connection-env", "NOPE_NOT_SET"]).exit_code == 2
    assert runner.invoke(cli_app, ["scan", "--connection-env", "X", "--mode", "behavioral"]).exit_code == 2
