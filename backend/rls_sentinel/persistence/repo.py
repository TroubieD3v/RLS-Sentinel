"""Repository layer for application metadata (SQLAlchemy 2)."""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, delete, event, func, inspect, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from ..catalog.models import Snapshot
from ..errors import Conflict, NotFound
from ..expectations.models import Spec
from ..harness.results import RunResult
from ..redaction import redact_obj
from .models import (
    AuditEvent,
    Base,
    CatalogObject,
    ConnectionProfile,
    ExpectationSpecRow,
    FindingReview,
    FindingRow,
    GrantRecord,
    JobRow,
    MembershipEdge,
    PolicyRecord,
    RoleRecord,
    SnapshotRow,
    Suppression,
    TestCaseResultRow,
    TestRun,
    WhatIfExperimentRow,
    Workspace,
    new_id,
    utcnow,
)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


_AUDIT_TABLE: Any = AuditEvent.__table__  # Core DELETE target for the retention purge


def _iso(dt: datetime | None) -> str | None:
    d = _aware(dt)
    return d.isoformat() if d else None


class Database:
    def __init__(self, url: str):
        kw: dict[str, Any] = {"future": True}
        if url.startswith("sqlite"):
            kw["connect_args"] = {"check_same_thread": False, "timeout": 30}
        else:
            kw["pool_pre_ping"] = True
        self.engine: Engine = create_engine(url, **kw)
        if url.startswith("sqlite"):
            @event.listens_for(self.engine, "connect")
            def _pragmas(dbapi_conn, _):
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA foreign_keys=ON")
                cur.execute("PRAGMA journal_mode=WAL")
                cur.close()
        self.Session = sessionmaker(self.engine, expire_on_commit=False)
        self.url_kind = "sqlite" if url.startswith("sqlite") else "postgresql"

    def init(self) -> None:
        """Bring the metadata store to the latest schema with Alembic.

        A store created before schema versioning existed (tables present, no ``alembic_version``) is stamped at the
        initial revision first, so upgrading never tries to re-create tables that already hold data.
        """
        from alembic import command
        from alembic.config import Config

        cfg = Config()
        cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
        existing = set(inspect(self.engine).get_table_names())
        with self.engine.begin() as conn:
            cfg.attributes["connection"] = conn
            if "alembic_version" not in existing and existing & set(Base.metadata.tables):
                command.stamp(cfg, "0001")
            command.upgrade(cfg, "head")

    @contextlib.contextmanager
    def session(self) -> Iterator[Session]:
        s = self.Session()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    def dispose(self) -> None:
        self.engine.dispose()

    # ------------------------------------------------------------------------------ audit
    def audit(self, actor: str, event_type: str, target: str = "", *, workspace_id: str | None = None, **detail: Any) -> None:
        with self.session() as s:
            s.add(AuditEvent(actor=actor, event_type=event_type, target=target[:300], workspace_id=workspace_id,
                             detail_json=redact_obj(detail)))

    def audit_events(self, workspace_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        with self.session() as s:
            q = select(AuditEvent).order_by(AuditEvent.timestamp.desc()).limit(limit)
            if workspace_id:
                q = q.where(AuditEvent.workspace_id == workspace_id)
            return [{"id": e.id, "workspace_id": e.workspace_id, "actor": e.actor, "event_type": e.event_type, "target": e.target,
                     "detail": e.detail_json, "timestamp": _iso(e.timestamp)} for e in s.scalars(q)]

    # ------------------------------------------------------------------------ workspaces
    def create_workspace(self, name: str, description: str, actor: str) -> dict[str, Any]:
        with self.session() as s:
            if s.scalar(select(Workspace).where(Workspace.name == name)):
                raise Conflict(f"Workspace '{name}' already exists.")
            w = Workspace(name=name, description=description)
            s.add(w)
            s.flush()
            out = self._ws(w)
        self.audit(actor, "workspace.create", name, workspace_id=out["id"])
        return out

    @staticmethod
    def _ws(w: Workspace) -> dict[str, Any]:
        return {"id": w.id, "name": w.name, "description": w.description, "created_at": _iso(w.created_at)}

    def list_workspaces(self) -> list[dict[str, Any]]:
        with self.session() as s:
            return [self._ws(w) for w in s.scalars(select(Workspace).order_by(Workspace.created_at))]

    def get_workspace(self, wid: str) -> dict[str, Any]:
        with self.session() as s:
            w = s.get(Workspace, wid)
            if not w:
                raise NotFound(f"Workspace {wid} not found.")
            return self._ws(w)

    def default_workspace(self, actor: str = "system") -> dict[str, Any]:
        ws = self.list_workspaces()
        if ws:
            return ws[0]
        return self.create_workspace("default", "Local workspace", actor)

    def delete_workspace(self, wid: str, actor: str) -> None:
        with self.session() as s:
            w = s.get(Workspace, wid)
            if not w:
                raise NotFound(f"Workspace {wid} not found.")
            for model in (WhatIfExperimentRow, FindingReview, Suppression):
                s.execute(delete(model).where(model.workspace_id == wid))
            s.execute(delete(FindingRow).where(FindingRow.workspace_id == wid))
            s.delete(w)
        self.audit(actor, "workspace.delete", wid, workspace_id=None)

    # ------------------------------------------------------------------------ connections
    def create_connection(self, workspace_id: str, *, kind: str, alias: str, mode: str, display_target: str | None,
                          pg_major: int | None, secret_ref: str, status: str | None, actor: str) -> dict[str, Any]:
        with self.session() as s:
            c = ConnectionProfile(workspace_id=workspace_id, kind=kind, target_alias=alias, mode=mode, display_target=display_target,
                                  pg_major_version=pg_major, secret_ref=secret_ref, last_connection_status=status)
            s.add(c)
            s.flush()
            out = self._conn(c)
        self.audit(actor, "connection.create", alias, workspace_id=workspace_id, kind=kind, mode=mode)
        return out

    @staticmethod
    def _conn(c: ConnectionProfile) -> dict[str, Any]:
        return {"id": c.id, "workspace_id": c.workspace_id, "kind": c.kind, "target_alias": c.target_alias, "mode": c.mode,
                "display_target": c.display_target, "pg_major_version": c.pg_major_version,
                "secret": {"stored": False, "reference": c.secret_ref if c.secret_ref.startswith("env:") else "session-only"},
                "last_connection_status": c.last_connection_status, "created_at": _iso(c.created_at)}

    def get_connection(self, cid: str) -> dict[str, Any]:
        with self.session() as s:
            c = s.get(ConnectionProfile, cid)
            if not c:
                raise NotFound(f"Connection {cid} not found.")
            return self._conn(c)

    def connection_secret_ref(self, cid: str) -> str:
        with self.session() as s:
            c = s.get(ConnectionProfile, cid)
            if not c:
                raise NotFound(f"Connection {cid} not found.")
            return c.secret_ref

    def list_connections(self, workspace_id: str | None = None) -> list[dict[str, Any]]:
        with self.session() as s:
            q = select(ConnectionProfile).order_by(ConnectionProfile.created_at)
            if workspace_id:
                q = q.where(ConnectionProfile.workspace_id == workspace_id)
            return [self._conn(c) for c in s.scalars(q)]

    def update_connection_status(self, cid: str, status: str) -> None:
        with self.session() as s:
            c = s.get(ConnectionProfile, cid)
            if c:
                c.last_connection_status = status[:300]

    # -------------------------------------------------------------------------- snapshots
    def save_snapshot(self, workspace_id: str, snap: Snapshot, *, project: str | None = None) -> str:
        with self.session() as s:
            row = SnapshotRow(workspace_id=workspace_id, project_id=project, source_kind=snap.source.kind, source_alias=snap.source.alias,
                              mode=snap.source.mode, schema_hash=snap.schema_hash, coverage_json=snap.coverage.model_dump(mode="json"),
                              postgres_version=snap.postgres_version, data_json=snap.model_dump(mode="json"))
            s.add(row)
            s.flush()
            for t in snap.tables:
                row.objects.append(CatalogObject(type=t.kind, schema=t.schema_name, qualified_name=t.qualified, owner=t.owner,
                                                 metadata_json=t.model_dump(mode="json", by_alias=True, exclude={"columns"})
                                                 | {"column_count": len(t.columns)}))
            for f in snap.functions:
                row.objects.append(CatalogObject(type="function", schema=f.schema_name, qualified_name=f.qualified, owner=f.owner,
                                                 metadata_json=f.model_dump(mode="json", by_alias=True)))
            for p in snap.policies:
                row.policies.append(PolicyRecord(table_ref=p.table, name=p.name, command=p.command, roles=p.roles, permissive=p.permissive,
                                                 using_expression=p.using_expr, with_check_expression=p.check_expr,
                                                 provenance_json=p.provenance.model_dump(mode="json")))
            for r in snap.roles:
                row.roles.append(RoleRecord(name=r.name, attributes_json=r.model_dump(mode="json", exclude={"provenance"})))
            for m in snap.memberships:
                row.memberships.append(MembershipEdge(role=m.role, member=m.member, inherit_option=m.inherit_option,
                                                      set_option=m.set_option, admin_option=m.admin_option))
            for g in snap.grants:
                row.grants.append(GrantRecord(object_type=g.object_type, object_name=g.object, grantee=g.grantee, privilege=g.privilege,
                                              grantable=g.grantable))
            return row.id

    def get_snapshot(self, sid: str) -> Snapshot:
        with self.session() as s:
            row = s.get(SnapshotRow, sid)
            if not row:
                raise NotFound(f"Snapshot {sid} not found.")
            return Snapshot.model_validate(row.data_json)

    def snapshot_meta(self, sid: str) -> dict[str, Any]:
        with self.session() as s:
            row = s.get(SnapshotRow, sid)
            if not row:
                raise NotFound(f"Snapshot {sid} not found.")
            return self._snap_meta(row)

    @staticmethod
    def _snap_meta(row: SnapshotRow) -> dict[str, Any]:
        return {"id": row.id, "workspace_id": row.workspace_id, "source_kind": row.source_kind, "source_alias": row.source_alias, "mode": row.mode,
                "schema_hash": row.schema_hash, "postgres_version": row.postgres_version, "coverage": row.coverage_json,
                "created_at": _iso(row.created_at)}

    def list_snapshots(self, workspace_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with self.session() as s:
            q = select(SnapshotRow).order_by(SnapshotRow.created_at.desc()).limit(limit)
            if workspace_id:
                q = q.where(SnapshotRow.workspace_id == workspace_id)
            return [self._snap_meta(r) for r in s.scalars(q)]

    def list_objects(self, sid: str, *, type_: str | None = None, q: str | None = None, offset: int = 0, limit: int = 100) -> tuple[list[dict], int]:
        with self.session() as s:
            base = select(CatalogObject).where(CatalogObject.snapshot_id == sid)
            if type_:
                base = base.where(CatalogObject.type == type_)
            if q:
                base = base.where(CatalogObject.qualified_name.ilike(f"%{q}%"))
            total = s.scalar(select(func.count()).select_from(base.subquery())) or 0
            rows = s.scalars(base.order_by(CatalogObject.qualified_name).offset(offset).limit(limit))
            return [{"type": o.type, "schema": o.schema, "qualified_name": o.qualified_name, "owner": o.owner, "metadata": o.metadata_json} for o in rows], total

    def list_policies(self, sid: str, *, table: str | None = None, offset: int = 0, limit: int = 200) -> tuple[list[dict], int]:
        with self.session() as s:
            base = select(PolicyRecord).where(PolicyRecord.snapshot_id == sid)
            if table:
                base = base.where(PolicyRecord.table_ref == table)
            total = s.scalar(select(func.count()).select_from(base.subquery())) or 0
            rows = s.scalars(base.order_by(PolicyRecord.table_ref, PolicyRecord.name).offset(offset).limit(limit))
            return [{"table": p.table_ref, "name": p.name, "command": p.command, "roles": p.roles, "permissive": p.permissive,
                     "using": p.using_expression, "with_check": p.with_check_expression, "provenance": p.provenance_json} for p in rows], total

    # ---------------------------------------------------------------------------- specs
    def save_spec(self, workspace_id: str, spec: Spec, checksum: str) -> str:
        with self.session() as s:
            row = s.scalar(select(ExpectationSpecRow).where(ExpectationSpecRow.workspace_id == workspace_id, ExpectationSpecRow.checksum == checksum))
            if row:
                return row.id
            row = ExpectationSpecRow(workspace_id=workspace_id, project=spec.project, version=spec.version,
                                     validated_json=spec.model_dump(mode="json"), checksum=checksum)
            s.add(row)
            s.flush()
            return row.id

    def get_spec(self, spec_id: str) -> Spec:
        with self.session() as s:
            row = s.get(ExpectationSpecRow, spec_id)
            if not row:
                raise NotFound(f"Spec {spec_id} not found.")
            return Spec.model_validate(row.validated_json)

    # ----------------------------------------------------------------------------- runs
    def create_run(self, workspace_id: str, *, kind: str, fixture: str | None, variant: str | None, job_id: str | None,
                   spec_id: str | None = None, environment_mode: str = "DISPOSABLE LAB", run_id: str | None = None) -> str:
        with self.session() as s:
            run = TestRun(id=run_id or new_id(), workspace_id=workspace_id, kind=kind, fixture=fixture, variant=variant, job_id=job_id,
                          expected_spec_id=spec_id, environment_mode=environment_mode, status="queued")
            s.add(run)
            s.flush()
            return run.id

    def mark_run(self, run_id: str, status: str, error: str | None = None) -> None:
        with self.session() as s:
            run = s.get(TestRun, run_id)
            if run:
                run.status = status
                run.error = error
                if status in ("completed", "failed", "cancelled"):
                    run.completed_at = utcnow()

    def complete_run(self, run_id: str, result: RunResult, snapshot_id: str | None, status: str | None = None) -> None:
        with self.session() as s:
            run = s.get(TestRun, run_id)
            if not run:
                raise NotFound(f"Run {run_id} not found.")
            run.status = status or result.info.status
            run.completed_at = utcnow()
            run.snapshot_id = snapshot_id
            run.coverage_json = result.coverage.model_dump(mode="json")
            run.version_info = {"tool": result.info.tool_version, "ruleset": result.info.ruleset_version, "postgres": result.info.postgres_version,
                                "server": result.info.server_kind, "schema_hash": result.info.schema_hash, "spec_checksum": result.info.spec_checksum,
                                "fixture_fingerprint": result.info.fixture_fingerprint, "duration_s": result.info.duration_s}
            slim = result.model_copy(update={"snapshot": None})
            run.result_json = redact_obj(slim.model_dump(mode="json"))
            s.execute(delete(TestCaseResultRow).where(TestCaseResultRow.run_id == run_id))
            s.execute(delete(FindingRow).where(FindingRow.run_id == run_id))
            for c in result.cases:
                s.add(TestCaseResultRow(run_id=run_id, test_id=c.case_id, actor=c.actor, resource=c.resource, operation=c.operation,
                                        expected=c.expected, observed=c.observed, result_status=c.status, sqlstate=c.sqlstate,
                                        environment_fingerprint=c.evidence.environment_hash,
                                        evidence_ref=redact_obj(c.evidence.model_dump(mode="json") | {"table": c.table, "via": c.via, "columns": c.columns}),
                                        duration_ms=c.duration_ms))
            for f in result.findings:
                s.add(FindingRow(id=f["id"], run_id=run_id, workspace_id=run.workspace_id, rule_id=f["rule_id"], severity=f["severity"],
                                 evidence_class=f["evidence_class"], subject=f["subject"][:400], reason=f["summary"],
                                 fingerprint=f["fingerprint"], data_json=redact_obj(f)))

    def get_run_meta(self, run_id: str) -> dict[str, Any]:
        with self.session() as s:
            run = s.get(TestRun, run_id)
            if not run:
                raise NotFound(f"Run {run_id} not found.")
            return self._run_meta(run)

    @staticmethod
    def _run_meta(run: TestRun) -> dict[str, Any]:
        return {"id": run.id, "workspace_id": run.workspace_id, "snapshot_id": run.snapshot_id, "spec_id": run.expected_spec_id, "job_id": run.job_id,
                "kind": run.kind, "fixture": run.fixture, "variant": run.variant, "environment_mode": run.environment_mode,
                "started_at": _iso(run.started_at), "completed_at": _iso(run.completed_at), "status": run.status,
                "version_info": run.version_info, "coverage": run.coverage_json, "error": run.error}

    def get_run_result(self, run_id: str) -> RunResult:
        with self.session() as s:
            run = s.get(TestRun, run_id)
            if not run:
                raise NotFound(f"Run {run_id} not found.")
            if not run.result_json:
                raise NotFound(f"Run {run_id} has no stored result yet (status {run.status}).")
            res = RunResult.model_validate(run.result_json)
            if run.snapshot_id:
                snap = s.get(SnapshotRow, run.snapshot_id)
                if snap:
                    res.snapshot = snap.data_json
            return res

    def list_runs(self, workspace_id: str | None = None, *, kind: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with self.session() as s:
            q = select(TestRun).order_by(TestRun.started_at.desc()).limit(limit)
            if workspace_id:
                q = q.where(TestRun.workspace_id == workspace_id)
            if kind:
                q = q.where(TestRun.kind == kind)
            return [self._run_meta(r) for r in s.scalars(q)]

    def list_cases(self, run_id: str, *, status: str | None = None, actor: str | None = None, offset: int = 0, limit: int = 500) -> tuple[list[dict], int]:
        with self.session() as s:
            base = select(TestCaseResultRow).where(TestCaseResultRow.run_id == run_id)
            if status:
                base = base.where(TestCaseResultRow.result_status == status)
            if actor:
                base = base.where(TestCaseResultRow.actor == actor)
            total = s.scalar(select(func.count()).select_from(base.subquery())) or 0
            rows = s.scalars(base.order_by(TestCaseResultRow.test_id).offset(offset).limit(limit))
            return [{"case_id": c.test_id, "actor": c.actor, "resource": c.resource, "operation": c.operation, "expected": c.expected,
                     "observed": c.observed, "status": c.result_status, "sqlstate": c.sqlstate,
                     "environment_fingerprint": c.environment_fingerprint, "evidence": c.evidence_ref, "duration_ms": c.duration_ms,
                     "table": (c.evidence_ref or {}).get("table"), "via": (c.evidence_ref or {}).get("via")} for c in rows], total

    def delete_run(self, run_id: str, actor: str) -> None:
        with self.session() as s:
            run = s.get(TestRun, run_id)
            if not run:
                raise NotFound(f"Run {run_id} not found.")
            ws = run.workspace_id
            s.execute(delete(WhatIfExperimentRow).where(WhatIfExperimentRow.baseline_run_id == run_id))
            s.delete(run)
        self.audit(actor, "run.delete", run_id, workspace_id=ws)

    def delete_snapshot(self, sid: str, actor: str) -> None:
        with self.session() as s:
            row = s.get(SnapshotRow, sid)
            if not row:
                raise NotFound(f"Snapshot {sid} not found.")
            ws = row.workspace_id
            s.delete(row)
        self.audit(actor, "snapshot.delete", sid, workspace_id=ws)

    # ------------------------------------------------------------------------- findings
    def _active_suppressions(self, s: Session, workspace_id: str | None) -> list[Suppression]:
        now = utcnow()
        q = select(Suppression).where(Suppression.revoked_at.is_(None))
        if workspace_id:
            q = q.where(Suppression.workspace_id == workspace_id)
        return [x for x in s.scalars(q) if (_aware(x.expires_at) or now) > now]

    @staticmethod
    def _match(sup: Suppression, f: dict[str, Any]) -> bool:
        return sup.rule_id == f["rule_id"] and (sup.scope in ("*", "") or f["subject"].startswith(sup.scope))

    def _decorate(self, s: Session, rows: list[FindingRow], workspace_id: str | None) -> list[dict[str, Any]]:
        sups = self._active_suppressions(s, workspace_id)
        wss = {r.workspace_id for r in rows}
        reviews = {(r.workspace_id, r.fingerprint): r for r in s.scalars(select(FindingReview).where(FindingReview.workspace_id.in_(wss)))} if wss else {}
        out = []
        for r in rows:
            f = dict(r.data_json)
            rv = reviews.get((r.workspace_id, r.fingerprint))
            if rv:
                f["lifecycle_state"], f["reviewer_note"] = rv.lifecycle_state, rv.reviewer_note
            m = next((x for x in sups if self._match(x, f)), None)
            if m:
                f["suppressed"] = True
                f["suppression"] = {"id": m.id, "reason": m.reason, "owner": m.owner, "reviewer": m.reviewer, "expires_at": _iso(m.expires_at), "scope": m.scope}
            f["run_id"] = r.run_id
            out.append(f)
        return out

    def list_findings(self, *, workspace_id: str | None = None, run_id: str | None = None, rule_id: str | None = None, severity: str | None = None,
                      evidence_class: str | None = None, lifecycle: str | None = None, q: str | None = None, include_suppressed: bool = False,
                      offset: int = 0, limit: int = 200) -> tuple[list[dict[str, Any]], int]:
        with self.session() as s:
            base = select(FindingRow)
            if workspace_id:
                base = base.where(FindingRow.workspace_id == workspace_id)
            if run_id:
                base = base.where(FindingRow.run_id == run_id)
            if rule_id:
                base = base.where(FindingRow.rule_id == rule_id)
            if severity:
                base = base.where(FindingRow.severity == severity)
            if evidence_class:
                base = base.where(FindingRow.evidence_class == evidence_class)
            if q:
                base = base.where(FindingRow.subject.ilike(f"%{q}%") | FindingRow.reason.ilike(f"%{q}%"))
            rows = list(s.scalars(base.order_by(FindingRow.created_at.desc())))
            items = self._decorate(s, rows, workspace_id)
            if not include_suppressed:
                items = [f for f in items if not f.get("suppressed")]
            if lifecycle:
                items = [f for f in items if f.get("lifecycle_state") == lifecycle]
            from ..reporting.builder import finding_sort_key

            items.sort(key=finding_sort_key)
            return items[offset:offset + limit], len(items)

    def get_finding(self, fid: str) -> dict[str, Any]:
        with self.session() as s:
            row = s.get(FindingRow, fid)
            if not row:
                raise NotFound(f"Finding {fid} not found.")
            return self._decorate(s, [row], row.workspace_id)[0]

    def review_finding(self, fid: str, state: str, note: str, actor: str) -> dict[str, Any]:
        with self.session() as s:
            row = s.get(FindingRow, fid)
            if not row:
                raise NotFound(f"Finding {fid} not found.")
            rv = s.scalar(select(FindingReview).where(FindingReview.workspace_id == row.workspace_id, FindingReview.fingerprint == row.fingerprint))
            if rv is None:
                rv = FindingReview(workspace_id=row.workspace_id, fingerprint=row.fingerprint)
                s.add(rv)
            rv.lifecycle_state, rv.reviewer_note, rv.reviewed_by, rv.updated_at = state, note, actor, utcnow()
            ws = row.workspace_id
        self.audit(actor, "finding.review", fid, workspace_id=ws, state=state)
        return self.get_finding(fid)

    # ---------------------------------------------------------------------- suppressions
    def create_suppression(self, workspace_id: str, *, rule_id: str, scope: str, reason: str, owner: str, reviewer: str,
                           expires_at: datetime, actor: str) -> dict[str, Any]:
        with self.session() as s:
            sup = Suppression(workspace_id=workspace_id, rule_id=rule_id, scope=scope or "*", reason=reason, owner=owner, reviewer=reviewer,
                              expires_at=expires_at)
            s.add(sup)
            s.flush()
            out = self._sup(sup)
        self.audit(actor, "suppression.create", f"{rule_id}:{scope}", workspace_id=workspace_id, reason=reason, owner=owner, reviewer=reviewer,
                   expires_at=_iso(expires_at))
        return out

    @staticmethod
    def _sup(x: Suppression) -> dict[str, Any]:
        return {"id": x.id, "workspace_id": x.workspace_id, "rule_id": x.rule_id, "scope": x.scope, "reason": x.reason, "owner": x.owner,
                "reviewer": x.reviewer, "expires_at": _iso(x.expires_at), "created_at": _iso(x.created_at), "revoked_at": _iso(x.revoked_at),
                "active": x.revoked_at is None and (_aware(x.expires_at) or utcnow()) > utcnow()}

    def list_suppressions(self, workspace_id: str | None = None) -> list[dict[str, Any]]:
        with self.session() as s:
            q = select(Suppression).order_by(Suppression.created_at.desc())
            if workspace_id:
                q = q.where(Suppression.workspace_id == workspace_id)
            return [self._sup(x) for x in s.scalars(q)]

    def revoke_suppression(self, sid: str, actor: str) -> dict[str, Any]:
        with self.session() as s:
            x = s.get(Suppression, sid)
            if not x:
                raise NotFound(f"Suppression {sid} not found.")
            x.revoked_at = utcnow()
            ws = x.workspace_id
            out = self._sup(x)
        self.audit(actor, "suppression.revoke", sid, workspace_id=ws)
        return out

    # ------------------------------------------------------------------------- what-if
    def create_whatif(self, workspace_id: str, baseline_run_id: str, draft_sql: str, job_id: str | None) -> str:
        with self.session() as s:
            w = WhatIfExperimentRow(workspace_id=workspace_id, baseline_run_id=baseline_run_id, proposed_policy_diff=draft_sql, job_id=job_id)
            s.add(w)
            s.flush()
            return w.id

    def complete_whatif(self, wid: str, result: dict[str, Any] | None, *, status: str, error: str | None = None,
                        resolved: int = 0, regressions: int = 0, verdict: str = "", sandbox_run_id: str | None = None) -> None:
        with self.session() as s:
            w = s.get(WhatIfExperimentRow, wid)
            if w:
                w.status, w.error, w.resolved_findings, w.new_regressions, w.verdict = status, error, resolved, regressions, verdict
                w.sandbox_run_id = sandbox_run_id
                w.result_json = redact_obj(result) if result else None

    def get_whatif(self, wid: str) -> dict[str, Any]:
        with self.session() as s:
            w = s.get(WhatIfExperimentRow, wid)
            if not w:
                raise NotFound(f"What-if experiment {wid} not found.")
            return {"id": w.id, "workspace_id": w.workspace_id, "baseline_run_id": w.baseline_run_id, "status": w.status, "verdict": w.verdict,
                    "resolved_findings": w.resolved_findings, "new_regressions": w.new_regressions, "created_at": _iso(w.created_at),
                    "error": w.error, "draft_sql": w.proposed_policy_diff, "result": w.result_json, "job_id": w.job_id}

    def list_whatifs(self, workspace_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        with self.session() as s:
            q = select(WhatIfExperimentRow).order_by(WhatIfExperimentRow.created_at.desc()).limit(limit)
            if workspace_id:
                q = q.where(WhatIfExperimentRow.workspace_id == workspace_id)
            return [{"id": w.id, "baseline_run_id": w.baseline_run_id, "status": w.status, "verdict": w.verdict,
                     "resolved_findings": w.resolved_findings, "new_regressions": w.new_regressions, "created_at": _iso(w.created_at)}
                    for w in s.scalars(q)]

    # ----------------------------------------------------------------------------- jobs
    def create_job(self, kind: str, workspace_id: str | None) -> str:
        with self.session() as s:
            j = JobRow(kind=kind, workspace_id=workspace_id)
            s.add(j)
            s.flush()
            return j.id

    def update_job(self, jid: str, **fields: Any) -> None:
        with self.session() as s:
            j = s.get(JobRow, jid)
            if j:
                for k, v in fields.items():
                    setattr(j, k, v)

    def get_job(self, jid: str) -> dict[str, Any]:
        with self.session() as s:
            j = s.get(JobRow, jid)
            if not j:
                raise NotFound(f"Job {jid} not found.")
            return {"id": j.id, "kind": j.kind, "status": j.status, "created_at": _iso(j.created_at), "started_at": _iso(j.started_at),
                    "finished_at": _iso(j.finished_at), "progress": j.progress_json, "result_ref": j.result_ref, "error": j.error}

    def fail_orphaned_jobs(self) -> int:
        """Jobs that were running when the process died can never finish - mark them failed on startup."""
        n = 0
        with self.session() as s:
            for j in s.scalars(select(JobRow).where(JobRow.status.in_(["queued", "running"]))):
                j.status, j.error, j.finished_at = "failed", "Server restarted before the job finished.", utcnow()
                n += 1
            for r in s.scalars(select(TestRun).where(TestRun.status.in_(["queued", "running"]))):
                r.status, r.error, r.completed_at = "failed", "Server restarted before the run finished.", utcnow()
            for w in s.scalars(select(WhatIfExperimentRow).where(WhatIfExperimentRow.status.in_(["queued", "running"]))):
                w.status, w.error = "failed", "Server restarted before the experiment finished."
        return n

    # ---------------------------------------------------------------------- retention
    def purge_older_than(self, days: int, actor: str = "retention") -> dict[str, int]:
        cutoff = utcnow() - timedelta(days=days)
        counts: dict[str, Any] = {"runs": 0, "snapshots": 0, "audit_events": 0}
        with self.session() as s:
            for run in list(s.scalars(select(TestRun).where(TestRun.started_at < cutoff))):
                s.execute(delete(WhatIfExperimentRow).where(WhatIfExperimentRow.baseline_run_id == run.id))
                s.delete(run)
                counts["runs"] += 1
            for snap in list(s.scalars(select(SnapshotRow).where(SnapshotRow.created_at < cutoff))):
                s.delete(snap)
                counts["snapshots"] += 1
        # audit purge is a deliberate retention operation executed with Core DELETE (ORM listeners guard accidental edits)
        with self.engine.begin() as conn:
            res = conn.execute(delete(_AUDIT_TABLE).where(_AUDIT_TABLE.c.timestamp < cutoff - timedelta(days=days)))
            counts["audit_events"] = res.rowcount or 0
        self.audit(actor, "retention.purge", f">{days}d", **counts)
        return counts

    def stats(self) -> dict[str, int]:
        with self.session() as s:
            return {"workspaces": s.scalar(select(func.count(Workspace.id))) or 0, "snapshots": s.scalar(select(func.count(SnapshotRow.id))) or 0,
                    "runs": s.scalar(select(func.count(TestRun.id))) or 0, "findings": s.scalar(select(func.count(FindingRow.id))) or 0}


def dumps(obj: Any) -> str:
    return json.dumps(obj, default=str)
