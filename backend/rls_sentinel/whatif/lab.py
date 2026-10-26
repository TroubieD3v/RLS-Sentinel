"""What-if Policy Lab: apply a draft policy change to a DISPOSABLE clone and replay the whole matrix.

Nothing here can reach a source database: the only connections are to the disposable fixture server, the draft
is restricted by an AST allow-list, and it runs as the (non-superuser) object owner role.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections import Counter
from datetime import UTC, datetime
from typing import Any

import psycopg
from pglast import parse_sql
from pglast.stream import RawStream
from psycopg import sql
from pydantic import BaseModel, Field

from ..catalog.models import Snapshot
from ..config import Settings
from ..diff.snapshot_diff import SnapshotDiff, diff_snapshots
from ..errors import SpecError
from ..expectations.loader import load_spec
from ..expectations.models import Spec
from ..harness.fixtures import Fixture, find_fixture, lint_draft_sql, provision_fixture
from ..harness.results import CaseResult, CoverageSummary, RunResult
from ..harness.runner import ProgressFn, run_spec, scan_fixture_snapshot
from ..harness.servers import DisposableServer, start_server
from ..rules.engine import evaluate

BANNER = "SIMULATED IN DISPOSABLE DATABASE — NO LIVE CHANGES"


class CaseDelta(BaseModel):
    case_id: str
    actor: str
    operation: str
    expected: str
    before: str
    after: str
    kind: str  # resolved | regression | broader_access | unchanged_failing | unchanged_passing | unknown_changed
    detail: str = ""


class WhatIfResult(BaseModel):
    format: str = "rls-sentinel-whatif/1"
    id: str
    banner: str = BANNER
    fixture: str
    variant: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    baseline_run_id: str
    baseline_schema_hash: str
    sandbox_schema_hash: str = ""
    postgres_version: str = ""
    draft_sql: str
    draft_sql_normalized: list[str] = Field(default_factory=list)
    applied_statements: int = 0
    apply_error: str | None = None
    baseline_coverage: CoverageSummary = Field(default_factory=CoverageSummary)
    sandbox_coverage: CoverageSummary = Field(default_factory=CoverageSummary)
    deltas: list[CaseDelta] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)
    verdict: str = "no_change"
    verdict_text: str = ""
    resolved_findings: list[dict[str, Any]] = Field(default_factory=list)
    new_findings: list[dict[str, Any]] = Field(default_factory=list)
    snapshot_diff: SnapshotDiff | None = None
    sandbox_run: RunResult | None = None
    duration_s: float = 0.0
    no_live_changes: bool = True


def split_statements(draft: str) -> list[str]:
    """Split with the PostgreSQL parser (handles dollar quotes, comments, semicolons in strings)."""
    stmts = parse_sql(draft)
    out = []
    for s in stmts:
        out.append(str(RawStream()(s)))
    return out


def _owner_role(snap: Snapshot, spec: Spec) -> str:
    owners = Counter(t.owner for t in snap.tables if t.qualified in {r.table for r in spec.resources} | {tc.table for tc in spec.tables})
    if not owners:
        owners = Counter(t.owner for t in snap.tables)
    if not owners:
        raise SpecError("Cannot determine the object owner role of the fixture.")
    return owners.most_common(1)[0][0]


def apply_draft(fdb, draft_sql: str, owner: str, statement_timeout_ms: int = 5000) -> tuple[int, str | None]:
    problems = lint_draft_sql(draft_sql)
    if problems:
        raise SpecError("Draft SQL rejected by the sandbox allow-list: " + "; ".join(problems[:3]), issues=[{"level": "error", "path": "draft_sql", "message": p} for p in problems])
    statements = split_statements(draft_sql)
    applied = 0
    with fdb.admin_connect(autocommit=False) as conn:
        try:
            conn.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(owner)))
            conn.execute(sql.SQL("SET LOCAL statement_timeout = {}").format(sql.Literal(statement_timeout_ms)))
            for st in statements:
                conn.execute(st)
                applied += 1
            conn.commit()
        except psycopg.Error as exc:
            conn.rollback()
            msg = (exc.diag.message_primary if hasattr(exc, "diag") and exc.diag.message_primary else str(exc)).strip()
            return applied, f"Statement {applied + 1} failed: {msg[:240]}"
    return applied, None


def _kind(b: CaseResult, a: CaseResult) -> str:
    if b.status == "FAIL" and a.status == "PASS":
        return "resolved"
    if b.status != "FAIL" and a.status == "FAIL":
        return "broader_access" if (a.expected in ("DENY", "NO_ROWS") and a.violation_kind == "unauthorized_access") else "regression"
    if b.status == "FAIL" and a.status == "FAIL":
        return "unchanged_failing"
    if b.status == a.status:
        return "unchanged_passing" if a.status == "PASS" else "unknown_changed" if a.status == "INCONCLUSIVE" else "unchanged_passing"
    return "unknown_changed"


def compare_runs(base: RunResult, sandbox: RunResult) -> tuple[list[CaseDelta], dict[str, int]]:
    bm = {c.case_id: c for c in base.cases}
    deltas: list[CaseDelta] = []
    for a in sandbox.cases:
        b = bm.get(a.case_id)
        if b is None:
            continue
        kind = _kind(b, a)
        detail = ""
        if kind == "regression":
            detail = "An authorized operation that worked before is now blocked." if a.violation_kind == "authorized_blocked" else a.reason
        elif kind == "broader_access":
            detail = "The change grants access that the spec denies (broader policy)."
        elif kind == "resolved":
            detail = "Previously failing expectation now holds."
        deltas.append(CaseDelta(case_id=a.case_id, actor=a.actor, operation=a.operation, expected=a.expected,
                                before=b.status, after=a.status, kind=kind, detail=detail))
    c = Counter(d.kind for d in deltas)
    summary = {k: c.get(k, 0) for k in ("resolved", "regression", "broader_access", "unchanged_failing", "unchanged_passing", "unknown_changed")}
    return deltas, summary


def run_whatif(
    settings: Settings,
    fixture: str | Fixture,
    variant: str,
    draft_sql: str,
    *,
    baseline: RunResult,
    spec: Spec | None = None,
    server: DisposableServer | None = None,
    backend: str | None = None,
    progress: ProgressFn | None = None,
    cancel: threading.Event | None = None,
    whatif_id: str | None = None,
) -> WhatIfResult:
    t0 = time.perf_counter()
    fx = fixture if isinstance(fixture, Fixture) else find_fixture(fixture, settings.fixtures_dir)
    spec = spec or load_spec(fx.spec_path(variant))
    emit = progress or (lambda e: None)
    # validate up-front so an obviously invalid draft never provisions anything
    problems = lint_draft_sql(draft_sql)
    if problems:
        raise SpecError("Draft SQL rejected by the sandbox allow-list: " + "; ".join(problems[:3]),
                        issues=[{"level": "error", "path": "draft_sql", "message": p} for p in problems])
    base_snap = Snapshot.model_validate(baseline.snapshot) if baseline.snapshot else None
    res = WhatIfResult(id=whatif_id or uuid.uuid4().hex[:12], fixture=fx.name, variant=variant, baseline_run_id=baseline.info.run_id,
                       baseline_schema_hash=baseline.info.schema_hash, draft_sql=draft_sql,
                       baseline_coverage=baseline.coverage, draft_sql_normalized=split_statements(draft_sql))
    own = server is None
    srv = server or start_server(settings, backend=backend)
    try:
        emit({"stage": "sandbox", "message": f"Provisioning disposable clone for {fx.name}:{variant}"})
        with provision_fixture(srv, fx, variant) as fdb:
            res.postgres_version = srv.version
            pre = scan_fixture_snapshot(fdb)
            owner = _owner_role(pre, spec)
            emit({"stage": "apply", "message": f"Applying draft as role {owner} (non-superuser), sandbox only"})
            res.applied_statements, res.apply_error = apply_draft(fdb, draft_sql, owner)
            if res.apply_error:
                res.verdict, res.verdict_text = "apply_failed", res.apply_error
                res.duration_s = round(time.perf_counter() - t0, 3)
                return res
            snap = scan_fixture_snapshot(fdb)
            res.sandbox_schema_hash = snap.schema_hash
            emit({"stage": "replay", "message": "Replaying the full authorization matrix against the modified clone"})
            run = run_spec(fdb, spec, snapshot=snap, progress=progress, cancel=cancel, run_id=f"wi-{res.id}")
            run.info.environment_mode = "SANDBOX REPLAY"
            findings = evaluate(snap, spec, run)
            run.findings = [f.model_dump(mode="json") for f in findings]
            run.snapshot = snap.model_dump(mode="json")
            res.sandbox_run = run
            res.sandbox_coverage = run.coverage
        if base_snap is not None:
            res.snapshot_diff = diff_snapshots(base_snap, Snapshot.model_validate(run.snapshot), baseline, run)
        res.deltas, res.summary = compare_runs(baseline, run)
        bf = {f["fingerprint"]: f for f in baseline.findings}
        sf = {f["fingerprint"]: f for f in run.findings}
        res.resolved_findings = [f for fp, f in bf.items() if fp not in sf and f["evidence_class"] == "CONFIRMED_VIOLATION"]
        res.new_findings = [f for fp, f in sf.items() if fp not in bf and f["evidence_class"] == "CONFIRMED_VIOLATION"]
        s = res.summary
        bad = s.get("regression", 0) + s.get("broader_access", 0)
        if s.get("resolved", 0) and not bad:
            res.verdict = "improves"
            res.verdict_text = f"{s['resolved']} failing expectation(s) now hold and no authorized behaviour regressed."
        elif s.get("resolved", 0) and bad:
            res.verdict = "mixed"
            res.verdict_text = f"{s['resolved']} resolved but {bad} new regression(s)/broader access - do not apply as is."
        elif bad:
            res.verdict = "regresses"
            res.verdict_text = f"{bad} expectation(s) newly fail (authorized access blocked or broader access)."
        else:
            res.verdict = "no_change"
            res.verdict_text = "No expectation changed status."
        res.duration_s = round(time.perf_counter() - t0, 3)
        emit({"stage": "completed", "message": res.verdict_text})
        return res
    finally:
        if own:
            srv.stop()
