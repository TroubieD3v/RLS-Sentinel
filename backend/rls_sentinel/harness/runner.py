"""Orchestrates one behavioral run against a provisioned disposable fixture database."""

from __future__ import annotations

import hashlib
import logging
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg import sql

from .. import RULESET_VERSION, __version__
from ..adapters.supabase import SYNTHETIC_WARNING, claim_settings
from ..catalog.connection import open_catalog_session
from ..catalog.introspect import Introspector
from ..catalog.models import Snapshot, SourceInfo
from ..errors import SpecError
from ..expectations.loader import check_internal_references, spec_checksum
from ..expectations.models import Expectation, Spec
from ..expectations.validate import validate_against_snapshot
from .classify import classify
from .executor import WorkerConnections, observe, run_with_retry
from .fixtures import HARNESS_ROLE, FixtureDatabase
from .ops import OpPlan, baseline_exists_query, baseline_row_query, build_plan
from .results import (
    Baseline,
    CaseEvidence,
    CaseResult,
    CoverageSummary,
    RawObservation,
    RunInfo,
    RunResult,
)

log = logging.getLogger("rls_sentinel.runner")
ProgressFn = Callable[[dict[str, Any]], None]


class Cancelled(Exception):
    pass


def scan_fixture_snapshot(fdb: FixtureDatabase, *, store_expressions: bool = True) -> Snapshot:
    """Catalog audit of the lab database, performed through the non-superuser harness login."""
    src = SourceInfo(kind="fixture", alias=f"{fdb.fixture.name}:{fdb.variant}", mode="DISPOSABLE LAB",
                     display_target=f"{fdb.server.kind}:{fdb.server.port}/{fdb.dbname}")
    sess = open_catalog_session(fdb.harness_dsn, allowed_targets=None)
    try:
        snap = Introspector(sess, source=src, store_expressions=store_expressions).run()
    finally:
        sess.close()
    return snap


def data_digest(fdb: FixtureDatabase) -> str:
    """Fingerprint of all user-table contents, computed by the fixture admin (never leaves the process)."""
    h = hashlib.sha256()
    with fdb.admin_connect(autocommit=True) as c:
        tables = c.execute(
            "SELECT n.nspname, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE c.relkind IN ('r','p') AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' "
            "ORDER BY 1, 2").fetchall()
        for s, t in tables:
            row = c.execute(sql.SQL(
                "SELECT md5(coalesce(string_agg(x::text, E'\\n' ORDER BY x::text), '')) FROM {} x"
            ).format(sql.Identifier(s, t))).fetchone()
            h.update(f"{s}.{t}:{row[0] if row else ''};".encode())
    return "sha256:" + h.hexdigest()


def _policy_digest(fdb: FixtureDatabase) -> str:
    with fdb.admin_connect(autocommit=True) as c:
        rows = c.execute(
            "SELECT string_agg(concat_ws('|', polrelid::regclass::text, polname, polcmd, polpermissive, polroles::text, "
            "pg_get_expr(polqual, polrelid), pg_get_expr(polwithcheck, polrelid)), E'\\n' ORDER BY 1) FROM pg_policy").fetchone()
        return "sha256:" + hashlib.sha256((rows[0] or "").encode()).hexdigest()


def _guc_settings(spec: Spec, exp: Expectation) -> list[tuple[str, str]] | None:
    if spec.identity_mode != "supabase_synthetic":
        return None
    actor = spec.actor(exp.actor)
    assert actor is not None
    claims = exp.claims_override if exp.claims_override is not None else actor.claims
    return claim_settings(claims) if claims else []


def run_spec(
    fdb: FixtureDatabase,
    spec: Spec,
    *,
    snapshot: Snapshot | None = None,
    progress: ProgressFn | None = None,
    cancel: threading.Event | None = None,
    run_id: str | None = None,
) -> RunResult:
    emit = progress or (lambda e: None)
    cancel = cancel or threading.Event()
    run_id = run_id or uuid.uuid4().hex[:12]
    t_start = time.perf_counter()
    info = RunInfo(
        run_id=run_id, project=spec.project, fixture=fdb.fixture.name, variant=fdb.variant,
        postgres_version=fdb.server.version, server_kind=fdb.server.kind, spec_checksum=spec_checksum(spec),
        fixture_fingerprint=fdb.fingerprint, tool_version=__version__, ruleset_version=RULESET_VERSION,
        identity_mode=spec.identity_mode, parallelism=spec.execution.parallelism,
    )
    result = RunResult(info=info, spec=spec.model_dump(mode="json"))

    def check_cancel() -> None:
        if cancel.is_set():
            raise Cancelled()

    try:
        # ---- stage 1: validate -------------------------------------------------------------
        emit({"stage": "validate", "message": "Validating spec against the fixture catalog"})
        issues = [i for i in check_internal_references(spec) if i["level"] == "error"]
        if issues:
            raise SpecError("Spec reference errors.", issues=issues)
        fdb.grant_harness([a.pg_role for a in spec.actors])
        emit({"stage": "snapshot", "message": "Reading catalog as the non-superuser harness role"})
        snap = snapshot or scan_fixture_snapshot(fdb)
        info.schema_hash = snap.schema_hash
        result.snapshot = snap.model_dump(mode="json")
        db_issues = validate_against_snapshot(spec, snap)
        errors = [i for i in db_issues if i["level"] == "error"]
        if errors:
            raise SpecError(f"Spec does not fit the fixture ({len(errors)} error(s)): {errors[0]['message']}", issues=db_issues)
        for w in (i for i in db_issues if i["level"] == "warning"):
            result.errors.append(f"warning: {w['message']}")
        check_cancel()

        # ---- stage 2: harness preconditions -----------------------------------------------
        with psycopg.connect(fdb.harness_dsn, connect_timeout=8) as hc:
            row = hc.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = session_user").fetchone()
            assert row is not None
            result.isolation.harness_superuser, result.isolation.harness_bypassrls = bool(row[0]), bool(row[1])
        if result.isolation.harness_superuser or result.isolation.harness_bypassrls:
            raise SpecError(f"Harness role {HARNESS_ROLE} must not be superuser/BYPASSRLS.")
        result.isolation.data_digest_before = data_digest(fdb)
        policy_before = _policy_digest(fdb)

        # ---- stage 3: baselines (fixture admin, independent of RLS) -------------------------
        emit({"stage": "baseline", "message": "Establishing resource existence with the fixture administrator"})
        resource_exists: dict[str, bool] = {}
        row_json: dict[str, dict[str, Any]] = {}
        need_row = {e.resource for e in spec.expectations if e.operation == "UPSERT" and e.resource}
        with fdb.admin_connect(autocommit=True) as ac:
            for r in spec.resources:
                q, p = baseline_exists_query(r)
                resource_exists[r.id] = (ac.execute(q, p).fetchone() or [0])[0] == 1
                if r.id in need_row and resource_exists[r.id]:
                    q2, p2 = baseline_row_query(r)
                    got = ac.execute(q2, p2).fetchone()
                    if got:
                        row_json[r.id] = dict(got[0])
        check_cancel()

        # ---- stage 4: plans ----------------------------------------------------------------
        plans: dict[str, OpPlan] = {}
        skipped: dict[str, str] = {}
        built = 0
        for exp in spec.expectations:
            if exp.operation != "SELECT" and exp.operation != "EXECUTE" and not spec.execution.allow_mutations:
                skipped[exp.id] = "Mutating cases are disabled (execution.allow_mutations: false)."
                continue
            if built >= spec.execution.max_statements:
                skipped[exp.id] = f"execution.max_statements ({spec.execution.max_statements}) reached."
                continue
            if exp.operation == "UPSERT" and exp.resource not in row_json:
                skipped[exp.id] = "UPSERT needs the target row to exist in the fixture."
                continue
            plans[exp.id] = build_plan(spec, exp, claims=None)
            built += 1

        # ---- stage 5: execute --------------------------------------------------------------
        total = len(plans)
        emit({"stage": "execute", "message": f"Executing {total} cases (parallelism {spec.execution.parallelism})", "total": total})
        workers = WorkerConnections(fdb.harness_dsn, spec.execution.statement_timeout_ms)
        raws: dict[str, RawObservation] = {}
        done = 0
        lock = threading.Lock()
        env_hash = fdb.fingerprint

        def work(exp: Expectation) -> None:
            nonlocal done
            if cancel.is_set():
                return
            plan = plans[exp.id]
            actor = spec.actor(exp.actor)
            assert actor is not None
            gucs = _guc_settings(spec, exp)
            rj = row_json.get(exp.resource or "") if plan.needs_row_json else None
            raw = run_with_retry(workers, lambda conn: observe(conn, plan, actor, guc_settings=gucs, row_json=rj))
            with lock:
                raws[exp.id] = raw
                done += 1
                emit({"stage": "execute", "done": done, "total": total, "case": exp.id, "observed": raw.observed})

        try:
            with ThreadPoolExecutor(max_workers=spec.execution.parallelism, thread_name_prefix="sentinel-case") as pool:
                futs = [pool.submit(work, e) for e in spec.expectations if e.id in plans]
                for f in futs:
                    f.result()
        finally:
            if cancel.is_set():
                workers.cancel_all()
            workers.close()
        check_cancel()

        # ---- stage 6: classify (controls first) ---------------------------------------------
        emit({"stage": "classify", "message": "Comparing observations with the independent expectations"})
        result.cases = _classify_all(spec, plans, raws, skipped, resource_exists, env_hash)
        result.isolation.statements_executed = len(raws)

        # ---- stage 7: teardown verification ---------------------------------------------------
        result.isolation.data_digest_after = data_digest(fdb)
        policy_after = _policy_digest(fdb)
        result.isolation.no_fixture_drift = (
            result.isolation.data_digest_before == result.isolation.data_digest_after and policy_before == policy_after)
        if not result.isolation.no_fixture_drift:
            result.errors.append("Fixture drift detected after the run; results are not trustworthy.")
        result.coverage = CoverageSummary.from_cases(result.cases, total=len(spec.expectations))
        if spec.identity_mode == "supabase_synthetic":
            result.coverage.notes.append(SYNTHETIC_WARNING)
        info.status = "completed"
    except Cancelled:
        info.status = "cancelled"
        result.coverage = CoverageSummary.from_cases(result.cases, total=len(spec.expectations))
    except Exception as exc:
        info.status = "failed"
        result.errors.append(f"{type(exc).__name__}: {str(exc)[:300]}")
        result.coverage = CoverageSummary.from_cases(result.cases, total=len(spec.expectations))
        info.completed_at = datetime.now(UTC)
        info.duration_s = round(time.perf_counter() - t_start, 3)
        emit({"stage": "failed", "message": str(exc)[:300]})
        raise
    info.completed_at = datetime.now(UTC)
    info.duration_s = round(time.perf_counter() - t_start, 3)
    emit({"stage": info.status, "message": f"Run {info.status}"})
    return result


def _classify_all(
    spec: Spec,
    plans: dict[str, OpPlan],
    raws: dict[str, RawObservation],
    skipped: dict[str, str],
    exists: dict[str, bool],
    env_hash: str,
) -> list[CaseResult]:
    out: dict[str, CaseResult] = {}

    def make(exp: Expectation, verdict_status, verdict) -> CaseResult:
        actor = spec.actor(exp.actor)
        assert actor is not None
        res = spec.resource(exp.resource) if exp.resource else None
        raw = raws.get(exp.id, RawObservation())
        plan = plans.get(exp.id)
        q = exp.table or (res.table if res else None)
        res_tenant = res.tenant if res else (exp.as_tenant or None)
        if exp.set_tenant:
            res_tenant = exp.set_tenant
        baseline = Baseline(target_exists=exists.get(res.id) if res else None)
        ev = CaseEvidence(
            observed_count=raw.row_count, environment_hash=env_hash, identity_adapter=spec.identity_mode,
            authentication_verified=False, sql=raw.sql_display or (plan.display if plan else ""), raw=raw,
            baseline=baseline, explanation=verdict.reason, notes=list(verdict.notes),
        )
        if spec.identity_mode == "supabase_synthetic":
            ev.notes.append(SYNTHETIC_WARNING)
        return CaseResult(
            case_id=exp.id, actor=actor.id, db_role=actor.pg_role, resource=res.id if res else None, table=q,
            operation=exp.operation, expected=exp.expected, observed=raw.observed, status=verdict_status,
            finding_class=verdict.finding_class, sqlstate=raw.sqlstate, gate=raw.gate, rule_hint=exp.rule or verdict.rule_hint,
            violation_kind=verdict.violation_kind, via=exp.via or exp.function, columns=list(exp.columns),
            moves_tenant=bool(exp.set_tenant), tenant_actor=actor.tenant, tenant_resource=res_tenant,
            tags=exp.tags, description=exp.description, reason=verdict.reason, evidence=ev,
            duration_ms=raw.duration_ms,
        )

    class _Skipped:
        finding_class = "INCONCLUSIVE"
        violation_kind = None
        rule_hint = None
        notes: tuple[str, ...] = ()

        def __init__(self, reason: str):
            self.reason = reason

    # pass 1: ALLOW cases (they double as positive controls for DENY cases on the same resource)
    control_status: dict[str, str] = {}
    control_ids: dict[str, str] = {}
    for exp in spec.expectations:
        if exp.id in skipped:
            out[exp.id] = make(exp, "SKIPPED", _Skipped(skipped[exp.id]))
            continue
        if exp.expected != "ALLOW":
            continue
        actor = spec.actor(exp.actor)
        assert actor is not None
        res = spec.resource(exp.resource) if exp.resource else None
        base = Baseline(target_exists=exists.get(res.id) if res else None)
        v = classify(exp, actor, raws[exp.id], base, control_status=None)
        out[exp.id] = make(exp, v.status, v)
        is_control = (exp.operation == "SELECT" and not exp.via and not exp.columns and exp.claims_override is None
                      and not actor.expect_bypass and res is not None)
        if is_control:
            assert res is not None
            # An INCONCLUSIVE case establishes nothing about accessibility, so it is not a usable control.
            if v.status in ("PASS", "FAIL", "ERROR") and control_status.get(res.id) != "PASS":
                control_status[res.id] = v.status
                control_ids[res.id] = exp.id
    # pass 2: everything else
    for exp in spec.expectations:
        if exp.id in out:
            continue
        actor = spec.actor(exp.actor)
        assert actor is not None
        res = spec.resource(exp.resource) if exp.resource else None
        base = Baseline(target_exists=exists.get(res.id) if res else None,
                        authorized_control=control_ids.get(res.id) if res else None,
                        authorized_control_status=control_status.get(res.id) if res else None)
        v = classify(exp, actor, raws[exp.id], base, control_status=control_status.get(res.id) if res else None)
        cr = make(exp, v.status, v)
        cr.evidence.baseline = base
        out[exp.id] = cr
    # preserve spec order
    return [out[e.id] for e in spec.expectations]
