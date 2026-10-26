"""Versioned REST API (``/api/v1``)."""

from __future__ import annotations

import contextlib
import json
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
from fastapi import APIRouter, Query, Request
from fastapi.responses import Response, StreamingResponse

from .. import RULESET_VERSION, __version__
from ..catalog.connection import open_catalog_session
from ..catalog.models import Snapshot
from ..diff.snapshot_diff import compare_findings, diff_snapshots, drift_findings
from ..errors import NotFound, SentinelError, SpecError
from ..expectations.loader import check_internal_references, load_spec_text, spec_checksum
from ..expectations.models import Spec
from ..expectations.validate import validate_against_snapshot
from ..findings.models import Finding
from ..graph.builder import access_paths, build_graph, subgraph
from ..harness.fixtures import discover_fixtures, find_fixture, lint_draft_sql
from ..harness.results import CoverageSummary, RunInfo, RunResult
from ..harness.runner import scan_fixture_snapshot
from ..persistence.repo import _iso
from ..redaction import redact_obj, safe_url_for_display
from ..reporting.builder import build_report
from ..reporting.exporters import FORMATS, render
from ..reporting.matrix import build_matrix
from ..reporting.pytest_export import generate_pytest
from ..rules.engine import evaluate
from ..rules.registry import RULES
from ..service import run_fixture_test, scan_source
from ..whatif.lab import BANNER, run_whatif
from ..whatif.suggest import build_suggestions, combine_sql
from .context import AppContext
from .jobs import Job
from .schemas import (
    ConnectionIn,
    ConnectionTestIn,
    DiffIn,
    FindingReviewIn,
    PurgeIn,
    ScanIn,
    SpecValidateIn,
    SuppressionIn,
    TestRunIn,
    WhatIfIn,
    WhatIfLintIn,
    WorkspaceIn,
)

router = APIRouter(prefix="/api/v1")


def ctx_of(request: Request) -> AppContext:
    return request.app.state.ctx


def actor_of(request: Request) -> str:
    return "api-token" if ctx_of(request).settings.api_token else "local-user"


def ok(data: Any, **meta: Any) -> dict[str, Any]:
    return {"data": data, "meta": meta}


def page(items: list[Any], total: int, offset: int, limit: int, **meta: Any) -> dict[str, Any]:
    return {"data": items, "meta": {"pagination": {"total": total, "offset": offset, "limit": limit, "returned": len(items)}, **meta}}


def _ws_id(c: AppContext, wid: str | None, actor: str) -> str:
    if wid:
        c.db.get_workspace(wid)
        return wid
    return c.db.default_workspace(actor)["id"]


# ===================================================================================== health / meta
@router.get("/health", tags=["meta"], summary="Health check (no secrets)")
def health(request: Request) -> dict[str, Any]:
    c = ctx_of(request)
    return ok({"status": "ok", "version": __version__, "ruleset": RULESET_VERSION, "lab": c.servers.availability(),
               "auth": "token" if c.settings.api_token else "localhost-single-user",
               "metadata_store": c.db.url_kind, "source_database_mutation": "never"})


@router.get("/settings", tags=["meta"], summary="Non-secret server configuration")
def server_settings(request: Request) -> dict[str, Any]:
    s = ctx_of(request).settings
    return ok({"host": s.host, "port": s.port, "allowed_targets": s.allowed_targets, "retention_days": s.retention_days,
               "store_expressions": s.store_expressions, "fixture_backend": s.fixture_backend,
               "default_statement_timeout_ms": s.default_statement_timeout_ms, "job_workers": s.job_workers,
               "auth_mode": "token" if s.api_token else "localhost-single-user", "version": __version__})


@router.get("/rules", tags=["meta"], summary="Versioned rule catalogue")
def rules() -> dict[str, Any]:
    return ok([{"id": r.id, "title": r.title, "description": r.description, "minimum_evidence": r.min_evidence, "category": r.category,
                "supports_static": r.supports_static, "supports_runtime": r.supports_runtime, "references": list(r.references),
                "remediation": r.remediation} for r in RULES.values()], ruleset=RULESET_VERSION)


@router.get("/schema/spec", tags=["expectations"], summary="JSON Schema of the expected-policy specification")
def spec_schema() -> dict[str, Any]:
    return ok(Spec.model_json_schema())


@router.get("/audit", tags=["meta"], summary="Audit log of state-changing actions")
def audit(request: Request, workspace_id: str | None = None, limit: int = Query(200, ge=1, le=1000)) -> dict[str, Any]:
    return ok(ctx_of(request).db.audit_events(workspace_id, limit))


# ===================================================================================== workspaces
@router.post("/workspaces", status_code=201, tags=["workspaces"], summary="Create project workspace")
def create_workspace(body: WorkspaceIn, request: Request) -> dict[str, Any]:
    return ok(ctx_of(request).db.create_workspace(body.name, body.description, actor_of(request)))


@router.get("/workspaces", tags=["workspaces"], summary="List workspaces")
def list_workspaces(request: Request) -> dict[str, Any]:
    c = ctx_of(request)
    c.db.default_workspace(actor_of(request))
    return ok(c.db.list_workspaces())


@router.delete("/workspaces/{wid}", status_code=204, tags=["workspaces"], summary="Delete a workspace and all of its stored results")
def delete_workspace(wid: str, request: Request) -> Response:
    ctx_of(request).db.delete_workspace(wid, actor_of(request))
    return Response(status_code=204)


# ===================================================================================== connections
def _dsn_for(c: AppContext, body: ConnectionTestIn) -> str:
    if body.dsn:
        return body.dsn
    if body.secret_ref:
        return c.vault.resolve("", body.secret_ref)
    raise SpecError("Provide either 'dsn' (session-only) or 'secret_ref' (env:VARIABLE).")


def _diagnose(c: AppContext, dsn: str) -> dict[str, Any]:
    sess = open_catalog_session(dsn, allowed_targets=c.settings.allowed_targets, statement_timeout_ms=5000)
    try:
        info = sess.fetch("server")[0]
        read_only_enforced = False
        try:
            with sess.savepoint():
                sess._conn.execute("CREATE TEMP TABLE sentinel_write_probe(x int)")
        except psycopg.errors.ReadOnlySqlTransaction:
            read_only_enforced = True
        except psycopg.Error:
            read_only_enforced = True
        can_policies = True
        try:
            with sess.savepoint():
                sess._conn.execute("SELECT count(*) FROM pg_policy")
        except psycopg.Error:
            can_policies = False
        diag = {
            "reachable": True, "postgres_version": info["version"], "database": info["database"], "inspector_role": info["current_user"],
            "is_superuser": info["is_superuser"], "bypasses_rls": info["bypass_rls"],
            "read_only_session_enforced": read_only_enforced, "can_read_pg_policy": can_policies,
            "mode": "READ-ONLY SOURCE", "supported_major": 15 <= info["version_num"] // 10000 <= 18,
            "warnings": [], "risk_notice": "Only bounded pg_catalog queries run against this database. No DDL/DML, no row data. Mutating tests run only in a disposable lab.",
        }
        if info["is_superuser"]:
            diag["warnings"].append("The inspection account is a superuser. Create a least-privilege role (docs/authorized-testing.md).")
        if info["bypass_rls"]:
            diag["warnings"].append("The inspection account has BYPASSRLS.")
        if not read_only_enforced:
            diag["warnings"].append("Could not confirm read-only enforcement.")
        return diag
    finally:
        sess.close()


@router.post("/connections/test", tags=["connections"], summary="Test an authorized catalog connection (read-only, allowlisted)")
def test_connection(body: ConnectionTestIn, request: Request) -> dict[str, Any]:
    c = ctx_of(request)
    dsn = _dsn_for(c, body)
    out = _diagnose(c, dsn)
    c.db.audit(actor_of(request), "connection.test", safe_url_for_display(dsn))
    return ok(out)


@router.post("/connections", status_code=201, tags=["connections"], summary="Register a connection reference (secret never stored)")
def create_connection(body: ConnectionIn, request: Request) -> dict[str, Any]:
    c = ctx_of(request)
    dsn = _dsn_for(c, body)
    diag = _diagnose(c, dsn)
    ws = _ws_id(c, body.workspace_id, actor_of(request))
    conn = c.db.create_connection(ws, kind="live_source", alias=body.alias, mode="READ-ONLY SOURCE", display_target=safe_url_for_display(dsn),
                                  pg_major=int(diag["postgres_version"].split(".")[0]) if diag.get("postgres_version") else None,
                                  secret_ref=body.secret_ref or "session", status="connected", actor=actor_of(request))
    if not body.secret_ref:
        c.vault.put(conn["id"], dsn)
    return ok(conn | {"diagnostics": diag})


@router.get("/connections", tags=["connections"], summary="List connection profiles (redacted)")
def list_connections(request: Request, workspace_id: str | None = None) -> dict[str, Any]:
    return ok(ctx_of(request).db.list_connections(workspace_id))


@router.get("/connections/{cid}", tags=["connections"], summary="Get redacted connection metadata")
def get_connection(cid: str, request: Request) -> dict[str, Any]:
    return ok(ctx_of(request).db.get_connection(cid))


@router.delete("/connections/{cid}", status_code=204, tags=["connections"], summary="Forget a connection and its session secret")
def delete_connection(cid: str, request: Request) -> Response:
    c = ctx_of(request)
    c.vault.drop(cid)
    with c.db.session() as s:
        from ..persistence.models import ConnectionProfile

        row = s.get(ConnectionProfile, cid)
        if row:
            s.delete(row)
    c.db.audit(actor_of(request), "connection.delete", cid)
    return Response(status_code=204)


# ===================================================================================== fixtures
@router.get("/fixtures", tags=["lab"], summary="Bundled synthetic fixtures")
def fixtures(request: Request) -> dict[str, Any]:
    c = ctx_of(request)
    return ok([f.summary() | {"expected_outcomes": f.expected} for f in discover_fixtures(c.settings.fixtures_dir)], lab=c.servers.availability())


@router.get("/fixtures/{name}", tags=["lab"], summary="Fixture details with its default expected-policy spec")
def fixture_detail(name: str, request: Request) -> dict[str, Any]:
    c = ctx_of(request)
    fx = find_fixture(name, c.settings.fixtures_dir)
    return ok(fx.summary() | {"expected_outcomes": fx.expected, "specs": {v: fx.spec_path(v).read_text(encoding="utf-8") for v in fx.variants},
                              "sql": {v: {p.name: p.read_text(encoding="utf-8") for p in fx.sql_files(v)} for v in fx.variants}})


# ===================================================================================== expectations
@router.post("/expectations/validate", tags=["expectations"], summary="Validate an expected-policy spec")
def validate_spec(body: SpecValidateIn, request: Request) -> dict[str, Any]:
    c = ctx_of(request)
    if body.spec is None and body.spec_object is None:
        raise SpecError("Provide 'spec' (text) or 'spec_object'.")
    try:
        spec = load_spec_text(body.spec, filename=body.filename) if body.spec is not None else \
            load_spec_text(json.dumps(body.spec_object), filename="spec.json")
    except SpecError as exc:
        return ok({"valid": False, "issues": exc.issues or [{"level": "error", "path": "", "message": exc.message}]})
    issues = check_internal_references(spec)
    if body.snapshot_id:
        issues += validate_against_snapshot(spec, c.db.get_snapshot(body.snapshot_id))
    errors = [i for i in issues if i["level"] == "error"]
    return ok({"valid": not errors, "issues": issues, "checksum": spec_checksum(spec), "normalized": spec.model_dump(mode="json"),
               "counts": {"actors": len(spec.actors), "resources": len(spec.resources), "expectations": len(spec.expectations),
                          "privileges": len(spec.privileges)}})


# ===================================================================================== scans (catalog snapshots)
def _catalog_result(snap: Snapshot, spec: Spec | None, mode: str, label: str) -> tuple[RunResult, list[Finding]]:
    findings = evaluate(snap, spec, None)
    info = RunInfo(run_id=uuid.uuid4().hex[:12], project=label, environment_mode=mode, postgres_version=snap.postgres_version,
                   schema_hash=snap.schema_hash, tool_version=__version__, ruleset_version=RULESET_VERSION, status="completed",
                   completed_at=datetime.now(UTC), duration_s=0.0)
    res = RunResult(info=info, coverage=CoverageSummary(), findings=[f.model_dump(mode="json") for f in findings], snapshot=snap.model_dump(mode="json"))
    return res, findings


@router.post("/scans", status_code=202, tags=["scans"], summary="Begin a read-only catalog scan (returns a job)")
def create_scan(body: ScanIn, request: Request) -> dict[str, Any]:
    c = ctx_of(request)
    actor = actor_of(request)
    ws = _ws_id(c, body.workspace_id, actor)
    if bool(body.connection_id) == bool(body.fixture):
        raise SpecError("Provide exactly one of 'connection_id' (live source, read-only) or 'fixture' (disposable lab).")
    if body.fixture and not body.variant:
        raise SpecError("'variant' is required with 'fixture'.")
    dsn = None
    alias = body.fixture or ""
    if body.connection_id:
        conn = c.db.get_connection(body.connection_id)
        alias = conn["target_alias"]
        dsn = c.vault.resolve(body.connection_id, c.db.connection_secret_ref(body.connection_id))

    def work(job: Job) -> str:
        def prog(stage: str, info: dict[str, Any]) -> None:
            job.emit("progress", {"stage": stage, **info})

        job.emit("progress", {"stage": "start", "message": "Starting read-only catalog scan" if dsn else "Provisioning disposable lab"})
        if dsn:
            snap = scan_source(dsn, c.settings, alias=alias, schemas=body.schemas, allow_privileged=body.allow_privileged, on_progress=prog)
            mode, spec = "READ-ONLY SOURCE", None
            res, _ = _catalog_result(snap, spec, mode, alias)
        else:
            assert body.fixture and body.variant
            fx = find_fixture(body.fixture, c.settings.fixtures_dir)
            spec = None
            from ..catalog.migrations import attach_migration_locations
            from ..expectations.loader import load_spec
            from ..harness.fixtures import provision_fixture

            spec = load_spec(fx.spec_path(body.variant))
            with provision_fixture(c.servers.get(), fx, body.variant) as fdb:
                snap = scan_fixture_snapshot(fdb)
                attach_migration_locations(snap, fx.sql_files(body.variant), fx.path)
            res, _ = _catalog_result(snap, spec, "DISPOSABLE LAB", f"{fx.name}:{body.variant}")
            res.info.fixture, res.info.variant = fx.name, body.variant
        if job.cancel.is_set():
            return ""
        sid = c.db.save_snapshot(ws, snap, project=alias)
        rid = c.db.create_run(ws, kind="catalog", fixture=res.info.fixture, variant=res.info.variant, job_id=job.id,
                              environment_mode=res.info.environment_mode, run_id=res.info.run_id)
        c.db.complete_run(rid, res, sid, "completed")
        c.db.audit(actor, "scan.complete", sid, workspace_id=ws, tables=snap.coverage.tables_seen, policies=snap.coverage.policies_seen)
        job.emit("result", {"snapshot_id": sid, "run_id": rid, "coverage": snap.coverage.model_dump(mode="json")})
        return sid

    job = c.jobs.submit("scan", ws, work)
    c.db.audit(actor, "scan.start", alias, workspace_id=ws, mode="READ-ONLY SOURCE" if dsn else "DISPOSABLE LAB")
    return ok({"id": job.id, "job_id": job.id, "status": job.status, "mode": "READ-ONLY SOURCE" if dsn else "DISPOSABLE LAB"})


def _snapshot_id(c: AppContext, ident: str) -> str:
    """Accept a scan job id or a snapshot id."""
    try:
        job = c.db.get_job(ident)
        if job["result_ref"]:
            return str(job["result_ref"])
        raise NotFound(f"Scan {ident} has not produced a snapshot yet (status {job['status']}).")
    except NotFound:
        c.db.snapshot_meta(ident)
        return ident


@router.get("/scans", tags=["scans"], summary="List stored catalog snapshots")
def list_scans(request: Request, workspace_id: str | None = None) -> dict[str, Any]:
    return ok(ctx_of(request).db.list_snapshots(workspace_id))


@router.get("/scans/{sid}", tags=["scans"], summary="Scan state and coverage manifest")
def get_scan(sid: str, request: Request) -> dict[str, Any]:
    c = ctx_of(request)
    try:
        job = c.db.get_job(sid)
    except NotFound:
        job = None
    if job is not None and not job["result_ref"]:
        return ok({"id": sid, "job": job, "status": job["status"], "snapshot": None, "error": job["error"]})
    snap_id = job["result_ref"] if job else sid
    meta = c.db.snapshot_meta(snap_id)
    return ok({"id": sid, "status": "completed", "snapshot": meta, "coverage": meta["coverage"], "job": job})


@router.get("/scans/{sid}/objects", tags=["scans"], summary="Catalog objects (paginated)")
def scan_objects(sid: str, request: Request, type: str | None = None, q: str | None = None, offset: int = Query(0, ge=0),
                 limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    c = ctx_of(request)
    items, total = c.db.list_objects(_snapshot_id(c, sid), type_=type, q=q, offset=offset, limit=limit)
    return page(items, total, offset, limit)


@router.get("/scans/{sid}/policies", tags=["scans"], summary="Policy explorer")
def scan_policies(sid: str, request: Request, table: str | None = None, offset: int = Query(0, ge=0), limit: int = Query(200, ge=1, le=500)) -> dict[str, Any]:
    c = ctx_of(request)
    items, total = c.db.list_policies(_snapshot_id(c, sid), table=table, offset=offset, limit=limit)
    return page(items, total, offset, limit)


@router.get("/scans/{sid}/snapshot", tags=["scans"], summary="Full normalized snapshot (policy text redacted)")
def scan_snapshot(sid: str, request: Request) -> dict[str, Any]:
    c = ctx_of(request)
    return ok(c.db.get_snapshot(_snapshot_id(c, sid)).model_dump(mode="json", by_alias=True))


def _graph_response(snap: Snapshot, spec: Spec | None, run: RunResult | None, findings: list[Finding], *, role: str | None, table: str | None,
                    tenant: str | None, finding: str | None, depth: int, max_nodes: int, hide: str | None) -> dict[str, Any]:
    g = build_graph(snap, spec, run, findings)
    focus = []
    if role:
        focus.append(f"role:{role}")
    if table:
        focus.append(f"table:{table}")
    if tenant:
        focus.append(f"tenant:{tenant}")
    if finding:
        focus.append(f"finding:{finding}")
    sg = subgraph(g, focus=focus or None, depth=depth, max_nodes=max_nodes, hide_types=set(hide.split(",")) if hide else None)
    return ok(sg.model_dump(mode="json"), truncated=sg.truncated)


@router.get("/scans/{sid}/graph", tags=["scans"], summary="Typed access graph (catalog facts and static inference)")
def scan_graph(sid: str, request: Request, role: str | None = None, table: str | None = None, depth: int = Query(2, ge=0, le=6),
               max_nodes: int = Query(400, ge=20, le=2000), hide: str | None = None) -> dict[str, Any]:
    c = ctx_of(request)
    snap_id = _snapshot_id(c, sid)
    snap = c.db.get_snapshot(snap_id)
    findings: list[Finding] = []
    for r in c.db.list_runs(kind="catalog", limit=500):
        if r["snapshot_id"] == snap_id:
            findings = [Finding.model_validate(f) for f in c.db.get_run_result(r["id"]).findings]
            break
    return _graph_response(snap, None, None, findings, role=role, table=table, tenant=None, finding=None, depth=depth, max_nodes=max_nodes, hide=hide)


@router.get("/scans/{sid}/access-paths", tags=["scans"], summary="How a role reaches tables: memberships, grants, policies, RLS outcome")
def scan_access_paths(sid: str, role: str, request: Request, table: str | None = None) -> dict[str, Any]:
    c = ctx_of(request)
    return ok(access_paths(c.db.get_snapshot(_snapshot_id(c, sid)), role, table))


# ===================================================================================== test runs
def _load_spec_for(body: TestRunIn, c: AppContext) -> Spec:
    from ..expectations.loader import load_spec

    if body.spec:
        return load_spec_text(body.spec, filename=body.filename)
    fx = find_fixture(body.fixture, c.settings.fixtures_dir)
    return load_spec(fx.spec_path(body.variant))


@router.post("/test-runs", status_code=202, tags=["test-runs"], summary="Schedule an isolated behavioral test run (returns a job)")
def create_test_run(body: TestRunIn, request: Request) -> dict[str, Any]:
    c = ctx_of(request)
    actor = actor_of(request)
    ws = _ws_id(c, body.workspace_id, actor)
    avail = c.servers.availability()
    if not avail["available"]:
        raise SentinelError(str(avail["detail"]), detail=avail)
    fx = find_fixture(body.fixture, c.settings.fixtures_dir)
    spec = _load_spec_for(body, c)
    checksum = spec_checksum(spec)
    spec_id = c.db.save_spec(ws, spec, checksum)
    holder: dict[str, str] = {}
    ready = threading.Event()

    def work(job: Job) -> str:
        if not ready.wait(10):
            raise RuntimeError("run record was not created")
        run_id = holder["run_id"]
        last_db = 0.0

        def progress(ev: dict[str, Any]) -> None:
            nonlocal last_db
            job.emit("progress", ev)
            now = datetime.now().timestamp()
            if now - last_db > 1.0:
                last_db = now
                c.db.update_job(job.id, progress_json=ev)

        c.db.mark_run(run_id, "running")
        try:
            result, snap = run_fixture_test(c.settings, fx, body.variant, spec=spec, server=c.servers.get(), progress=progress,
                                            cancel=job.cancel, run_id=run_id, only=body.only)
            sid = c.db.save_snapshot(ws, snap, project=spec.project)
            c.db.complete_run(run_id, result, sid)
            c.db.audit(actor, "test_run.complete", run_id, workspace_id=ws, status=result.info.status, failed=result.coverage.failed)
            job.emit("result", {"run_id": run_id, "coverage": result.coverage.model_dump(mode="json")})
            return run_id
        except Exception as exc:
            c.db.mark_run(run_id, "cancelled" if job.cancel.is_set() else "failed", str(exc)[:400])
            raise

    job = c.jobs.submit("test_run", ws, lambda j: work(j))
    run_id = c.db.create_run(ws, kind="lab", fixture=fx.name, variant=body.variant, job_id=job.id, spec_id=spec_id)
    holder["run_id"] = run_id
    ready.set()
    c.db.audit(actor, "test_run.start", run_id, workspace_id=ws, fixture=fx.name, variant=body.variant, cases=len(spec.expectations))
    return ok({"id": run_id, "run_id": run_id, "job_id": job.id, "status": "queued", "environment": "DISPOSABLE LAB", "total_cases": len(spec.expectations)})


@router.get("/test-runs", tags=["test-runs"], summary="List runs")
def list_runs(request: Request, workspace_id: str | None = None, kind: str | None = None, limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    return ok(ctx_of(request).db.list_runs(workspace_id, kind=kind, limit=limit))


@router.get("/test-runs/{rid}", tags=["test-runs"], summary="Progress and summary")
def get_run(rid: str, request: Request) -> dict[str, Any]:
    c = ctx_of(request)
    meta = c.db.get_run_meta(rid)
    job = c.jobs.get(meta["job_id"]) if meta.get("job_id") else None
    progress = None
    if job and job.events:
        last = [e for e in job.events if e["type"] == "progress"]
        progress = last[-1]["data"] if last else None
    elif meta.get("job_id"):
        with contextlib.suppress(NotFound):
            progress = c.db.get_job(meta["job_id"]).get("progress")
    summary = None
    if meta["status"] in ("completed", "cancelled"):
        res = c.db.get_run_result(rid)
        summary = {"coverage": res.coverage.model_dump(mode="json"), "panel": res.coverage.panel(), "isolation": res.isolation.model_dump(mode="json"),
                   "findings": len(res.findings), "errors": res.errors, "info": res.info.model_dump(mode="json")}
    return ok(meta | {"progress": progress, "summary": summary})


@router.post("/test-runs/{rid}/cancel", tags=["test-runs"], summary="Stop a bounded run (cooperative)")
def cancel_run(rid: str, request: Request) -> dict[str, Any]:
    c = ctx_of(request)
    meta = c.db.get_run_meta(rid)
    cancelled = bool(meta.get("job_id")) and c.jobs.cancel(meta["job_id"])
    c.db.audit(actor_of(request), "test_run.cancel", rid, workspace_id=meta["workspace_id"], accepted=cancelled)
    return ok({"run_id": rid, "cancel_requested": cancelled})


@router.get("/test-runs/{rid}/matrix", tags=["test-runs"], summary="Authorization matrix built only from executed cases")
def run_matrix(rid: str, request: Request) -> dict[str, Any]:
    c = ctx_of(request)
    res = c.db.get_run_result(rid)
    spec = Spec.model_validate(res.spec) if res.spec else None
    return ok(build_matrix(res, spec))


@router.get("/test-runs/{rid}/cases", tags=["test-runs"], summary="Individual case results with sanitized evidence")
def run_cases(rid: str, request: Request, status: str | None = None, actor: str | None = None, offset: int = Query(0, ge=0),
              limit: int = Query(500, ge=1, le=1000)) -> dict[str, Any]:
    items, total = ctx_of(request).db.list_cases(rid, status=status, actor=actor, offset=offset, limit=limit)
    return page(items, total, offset, limit)


@router.get("/test-runs/{rid}/graph", tags=["test-runs"], summary="Access graph overlaid with runtime evidence and findings")
def run_graph(rid: str, request: Request, role: str | None = None, table: str | None = None, tenant: str | None = None, finding: str | None = None,
              depth: int = Query(2, ge=0, le=6), max_nodes: int = Query(400, ge=20, le=2000), hide: str | None = None) -> dict[str, Any]:
    c = ctx_of(request)
    res = c.db.get_run_result(rid)
    if not res.snapshot:
        raise NotFound("This run has no catalog snapshot.")
    snap = Snapshot.model_validate(res.snapshot)
    spec = Spec.model_validate(res.spec) if res.spec else None
    findings = [Finding.model_validate(f) for f in res.findings]
    return _graph_response(snap, spec, res, findings, role=role, table=table, tenant=tenant, finding=finding, depth=depth, max_nodes=max_nodes, hide=hide)


@router.get("/test-runs/{rid}/events", tags=["test-runs"], summary="Server-sent events (heartbeat, resumable with Last-Event-ID)")
def run_events(rid: str, request: Request, after: int = 0) -> StreamingResponse:
    c = ctx_of(request)
    meta = c.db.get_run_meta(rid)
    last_id = request.headers.get("last-event-id")
    start = int(last_id) if last_id and last_id.isdigit() else after
    return StreamingResponse(c.jobs.stream(meta["job_id"], start), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@router.get("/jobs/{jid}", tags=["jobs"], summary="Job state")
def get_job(jid: str, request: Request) -> dict[str, Any]:
    return ok(ctx_of(request).db.get_job(jid))


@router.get("/jobs/{jid}/events", tags=["jobs"], summary="Server-sent events for any job")
def job_events(jid: str, request: Request, after: int = 0) -> StreamingResponse:
    c = ctx_of(request)
    last_id = request.headers.get("last-event-id")
    start = int(last_id) if last_id and last_id.isdigit() else after
    return StreamingResponse(c.jobs.stream(jid, start), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@router.post("/jobs/{jid}/cancel", tags=["jobs"], summary="Cancel any job")
def cancel_job(jid: str, request: Request) -> dict[str, Any]:
    return ok({"job_id": jid, "cancel_requested": ctx_of(request).jobs.cancel(jid)})


@router.delete("/test-runs/{rid}", status_code=204, tags=["test-runs"], summary="Delete a run and its evidence")
def delete_run(rid: str, request: Request) -> Response:
    ctx_of(request).db.delete_run(rid, actor_of(request))
    return Response(status_code=204)


@router.get("/test-runs/{rid}/suggestions", tags=["test-runs"], summary="Reviewable remediation SQL (never applied automatically)")
def run_suggestions(rid: str, request: Request) -> dict[str, Any]:
    c = ctx_of(request)
    res = c.db.get_run_result(rid)
    if not res.snapshot:
        raise NotFound("This run has no catalog snapshot.")
    snap = Snapshot.model_validate(res.snapshot)
    sugg = build_suggestions(snap, [Finding.model_validate(f) for f in res.findings])
    return ok({"suggestions": [s.model_dump() for s in sugg], "combined_sql": combine_sql(sugg) if sugg else "",
               "notice": "Suggestions are hypotheses. They are verified only by replaying them in the What-if Lab (disposable database)."})


@router.get("/test-runs/{rid}/pytest", tags=["test-runs"], summary="Generated pytest regression suite")
def run_pytest(rid: str, request: Request, mode: str = Query("spec", pattern="^(spec|pin)$")) -> Response:
    c = ctx_of(request)
    res = c.db.get_run_result(rid)
    if not res.spec or not res.info.fixture:
        raise NotFound("Only fixture-based runs can export a pytest suite.")
    text = generate_pytest(Spec.model_validate(res.spec), fixture=res.info.fixture, variant=res.info.variant or "vulnerable", run=res, mode=mode)
    return Response(text, media_type="text/x-python", headers={"Content-Disposition": 'attachment; filename="test_rls_authorization.py"'})


# ===================================================================================== findings
@router.get("/findings", tags=["findings"], summary="Search findings (suppressed hidden unless requested)")
def list_findings(request: Request, workspace_id: str | None = None, run_id: str | None = None, rule_id: str | None = None, severity: str | None = None,
                  evidence_class: str | None = None, lifecycle: str | None = None, q: str | None = None, include_suppressed: bool = False,
                  offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    items, total = ctx_of(request).db.list_findings(workspace_id=workspace_id, run_id=run_id, rule_id=rule_id, severity=severity,
                                                    evidence_class=evidence_class, lifecycle=lifecycle, q=q,
                                                    include_suppressed=include_suppressed, offset=offset, limit=limit)
    return page(items, total, offset, limit)


@router.get("/findings/{fid}", tags=["findings"], summary="Finding with full evidence")
def get_finding(fid: str, request: Request) -> dict[str, Any]:
    return ok(ctx_of(request).db.get_finding(fid))


@router.patch("/findings/{fid}", tags=["findings"], summary="Record a review decision")
def review_finding(fid: str, body: FindingReviewIn, request: Request) -> dict[str, Any]:
    return ok(ctx_of(request).db.review_finding(fid, body.lifecycle_state, body.reviewer_note, actor_of(request)))


@router.get("/suppressions", tags=["findings"], summary="List suppressions")
def list_suppressions(request: Request, workspace_id: str | None = None) -> dict[str, Any]:
    return ok(ctx_of(request).db.list_suppressions(workspace_id))


@router.post("/suppressions", status_code=201, tags=["findings"], summary="Suppress a rule with reason, owner, reviewer and expiry")
def create_suppression(body: SuppressionIn, request: Request) -> dict[str, Any]:
    c = ctx_of(request)
    exp = body.expires_at if body.expires_at.tzinfo else body.expires_at.replace(tzinfo=UTC)
    now = datetime.now(UTC)
    if exp <= now:
        raise SpecError("Suppression expiry must be in the future.")
    if exp > now + timedelta(days=366):
        raise SpecError("Suppressions may last at most one year; re-review is mandatory.")
    ws = _ws_id(c, body.workspace_id, actor_of(request))
    return ok(c.db.create_suppression(ws, rule_id=body.rule_id, scope=body.scope, reason=body.reason, owner=body.owner,
                                      reviewer=body.reviewer, expires_at=exp, actor=actor_of(request)))


@router.delete("/suppressions/{sid}", tags=["findings"], summary="Revoke a suppression (audited, result data unchanged)")
def revoke_suppression(sid: str, request: Request) -> dict[str, Any]:
    return ok(ctx_of(request).db.revoke_suppression(sid, actor_of(request)))


# ===================================================================================== what-if
@router.post("/what-if/lint", tags=["what-if"], summary="Check a draft against the sandbox allow-list (no execution)")
def whatif_lint(body: WhatIfLintIn) -> dict[str, Any]:
    problems = lint_draft_sql(body.draft_sql)
    return ok({"accepted": not problems, "problems": problems, "banner": BANNER})


@router.post("/what-if", status_code=202, tags=["what-if"], summary="Submit a sandbox-only policy proposal")
def create_whatif(body: WhatIfIn, request: Request) -> dict[str, Any]:
    c = ctx_of(request)
    actor = actor_of(request)
    meta = c.db.get_run_meta(body.run_id)
    if meta["kind"] != "lab" or not meta.get("fixture"):
        raise SpecError("What-if experiments need a baseline lab run on a fixture.")
    problems = lint_draft_sql(body.draft_sql)
    if problems:
        raise SpecError("Draft SQL rejected by the sandbox allow-list: " + "; ".join(problems[:3]),
                        issues=[{"level": "error", "path": "draft_sql", "message": p} for p in problems])
    baseline = c.db.get_run_result(body.run_id)
    holder: dict[str, str] = {}
    ready = threading.Event()

    def work(job: Job) -> str:
        if not ready.wait(10):
            raise RuntimeError("experiment record was not created")
        wid = holder["wid"]
        c.db.complete_whatif(wid, None, status="running")
        try:
            res = run_whatif(c.settings, meta["fixture"], meta["variant"], body.draft_sql, baseline=baseline, server=c.servers.get(),
                             progress=lambda ev: job.emit("progress", ev), cancel=job.cancel, whatif_id=wid)
            sandbox_run_id = None
            if res.sandbox_run is not None:
                ws = meta["workspace_id"]
                snap = Snapshot.model_validate(res.sandbox_run.snapshot) if res.sandbox_run.snapshot else None
                sid = c.db.save_snapshot(ws, snap, project=f"what-if {wid}") if snap else None
                sandbox_run_id = c.db.create_run(ws, kind="whatif_sandbox", fixture=meta["fixture"], variant=meta["variant"], job_id=job.id,
                                                 environment_mode="SANDBOX REPLAY", run_id=res.sandbox_run.info.run_id)
                c.db.complete_run(sandbox_run_id, res.sandbox_run, sid, "completed")
            payload = res.model_dump(mode="json", exclude={"sandbox_run"})
            c.db.complete_whatif(wid, payload, status="completed" if not res.apply_error else "failed", error=res.apply_error,
                                 resolved=res.summary.get("resolved", 0), regressions=res.summary.get("regression", 0) + res.summary.get("broader_access", 0),
                                 verdict=res.verdict, sandbox_run_id=sandbox_run_id)
            c.db.audit(actor, "whatif.complete", wid, workspace_id=meta["workspace_id"], verdict=res.verdict)
            return wid
        except Exception as exc:
            c.db.complete_whatif(wid, None, status="failed", error=str(exc)[:400])
            raise

    job = c.jobs.submit("what_if", meta["workspace_id"], work)
    wid = c.db.create_whatif(meta["workspace_id"], body.run_id, body.draft_sql, job.id)
    holder["wid"] = wid
    ready.set()
    c.db.audit(actor, "whatif.start", wid, workspace_id=meta["workspace_id"], baseline_run=body.run_id)
    return ok({"id": wid, "job_id": job.id, "status": "queued", "banner": BANNER})


@router.get("/what-if", tags=["what-if"], summary="List experiments")
def list_whatifs(request: Request, workspace_id: str | None = None) -> dict[str, Any]:
    return ok(ctx_of(request).db.list_whatifs(workspace_id))


@router.get("/what-if/{wid}", tags=["what-if"], summary="Diff and results")
def get_whatif(wid: str, request: Request) -> dict[str, Any]:
    return ok(ctx_of(request).db.get_whatif(wid) | {"banner": BANNER})


# ===================================================================================== diff / history
@router.post("/diff", tags=["history"], summary="Compare two snapshots/runs: policy drift and test-outcome differences")
def diff(body: DiffIn, request: Request) -> dict[str, Any]:
    c = ctx_of(request)

    def side(run_id: str | None, snap_id: str | None, js: dict[str, Any] | None) -> tuple[Snapshot, RunResult | None, list[Finding]]:
        if js is not None:
            if js.get("format", "").startswith("rls-sentinel-run"):
                r = RunResult.model_validate(js)
                return Snapshot.model_validate(r.snapshot), r, [Finding.model_validate(f) for f in r.findings]
            return Snapshot.model_validate(js), None, []
        if run_id:
            r = c.db.get_run_result(run_id)
            if not r.snapshot:
                raise NotFound(f"Run {run_id} has no snapshot.")
            return Snapshot.model_validate(r.snapshot), r, [Finding.model_validate(f) for f in r.findings]
        if snap_id:
            return c.db.get_snapshot(snap_id), None, []
        raise SpecError("Each side needs a run id, a snapshot id or JSON.")

    a, ra, fa = side(body.from_run_id, body.from_snapshot_id, body.from_json)
    b, rb, fb = side(body.to_run_id, body.to_snapshot_id, body.to_json)
    d = diff_snapshots(a, b, ra, rb)
    labels = compare_findings(fa, fb, after_has_runtime=rb is not None and bool(rb.cases))
    drift = drift_findings(d)
    return ok({"diff": d.model_dump(mode="json"), "finding_labels": labels, "drift_findings": [f.model_dump(mode="json") for f in drift]})


@router.get("/history", tags=["history"], summary="Run history with real coverage and finding counts")
def history(request: Request, workspace_id: str | None = None, fixture: str | None = None, limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    c = ctx_of(request)
    out = []
    for r in c.db.list_runs(workspace_id, limit=limit):
        if fixture and r["fixture"] != fixture:
            continue
        cov = r["coverage"] or {}
        findings, total = c.db.list_findings(run_id=r["id"], include_suppressed=True, limit=500)
        by_class: dict[str, int] = {}
        for f in findings:
            by_class[f["evidence_class"]] = by_class.get(f["evidence_class"], 0) + 1
        out.append({"run_id": r["id"], "kind": r["kind"], "started_at": r["started_at"], "status": r["status"], "fixture": r["fixture"],
                    "variant": r["variant"], "environment_mode": r["environment_mode"], "schema_hash": (r["version_info"] or {}).get("schema_hash"),
                    "expected": cov.get("expected_assertions", 0), "passed": cov.get("passed", 0), "failed": cov.get("failed", 0),
                    "inconclusive": cov.get("inconclusive", 0), "verified_coverage_pct": cov.get("verified_coverage_pct", 0),
                    "findings": total, "by_evidence_class": by_class})
    return ok(out)


# ===================================================================================== reports
@router.get("/reports/{rid}", tags=["reports"], summary="Export a run in an explicit format (json, md, html, sarif, csv)")
def report(rid: str, request: Request, format: str = Query("json"), full: bool = False, spec_uri: str | None = None) -> Response:
    c = ctx_of(request)
    if format.lower() not in FORMATS:
        raise SpecError(f"Unknown format '{format}'. Choose one of: json, md, html, sarif, csv.")
    res = c.db.get_run_result(rid)
    findings, _ = c.db.list_findings(run_id=rid, include_suppressed=True, limit=500)
    rep = build_report(res, findings, include_snapshot=full, spec_path=spec_uri)
    try:
        body, mime = render(rep, format, spec_uri=spec_uri)
    except ValueError as exc:
        raise SentinelError(str(exc)) from exc
    ext = {"markdown": "md"}.get(format.lower(), format.lower())
    c.db.audit(actor_of(request), "report.export", rid, format=ext)
    return Response(body, media_type=mime, headers={"Content-Disposition": f'attachment; filename="rls-sentinel-{rid}.{ext}"'})


# ===================================================================================== data lifecycle
@router.delete("/snapshots/{sid}", status_code=204, tags=["retention"], summary="Delete a stored snapshot")
def delete_snapshot(sid: str, request: Request) -> Response:
    ctx_of(request).db.delete_snapshot(sid, actor_of(request))
    return Response(status_code=204)


@router.post("/retention/purge", tags=["retention"], summary="Delete stored runs, snapshots and old audit data older than N days")
def purge(body: PurgeIn, request: Request) -> dict[str, Any]:
    return ok(ctx_of(request).db.purge_older_than(body.days, actor_of(request)))


@router.get("/stats", tags=["meta"], summary="Counts of stored objects")
def stats(request: Request) -> dict[str, Any]:
    return ok(ctx_of(request).db.stats())


_ = (redact_obj, _iso)  # re-exported helpers used by tests
