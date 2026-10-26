"""High-level orchestration shared by the CLI and the API."""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from typing import Any

from .catalog.connection import open_catalog_session
from .catalog.introspect import Introspector
from .catalog.migrations import attach_migration_locations
from .catalog.models import Snapshot, SourceInfo
from .config import Settings
from .expectations.loader import load_spec
from .expectations.models import Spec
from .harness.fixtures import Fixture, find_fixture, provision_fixture
from .harness.results import RunResult
from .harness.runner import ProgressFn, run_spec, scan_fixture_snapshot
from .harness.servers import DisposableServer, start_server
from .redaction import safe_url_for_display
from .rules.engine import evaluate


def scan_source(
    dsn: str,
    settings: Settings,
    *,
    alias: str = "source",
    schemas: list[str] | None = None,
    allow_privileged: bool = False,
    on_progress: Callable[[str, dict[str, Any]], None] | None = None,
) -> Snapshot:
    """Read-only catalog audit of an authorized live database (bounded catalog queries only)."""
    sess = open_catalog_session(dsn, allowed_targets=settings.allowed_targets)
    try:
        src = SourceInfo(kind="live_source", alias=alias, mode="READ-ONLY SOURCE", display_target=safe_url_for_display(dsn))
        return Introspector(sess, source=src, schemas=schemas, store_expressions=settings.store_expressions,
                            allow_privileged_inspector=allow_privileged, on_progress=on_progress).run()
    finally:
        sess.close()


def run_fixture_test(
    settings: Settings,
    fixture: str | Fixture,
    variant: str,
    *,
    spec: Spec | None = None,
    server: DisposableServer | None = None,
    backend: str | None = None,
    progress: ProgressFn | None = None,
    cancel: threading.Event | None = None,
    run_id: str | None = None,
    only: list[str] | None = None,
    trusted: bool | None = None,
) -> tuple[RunResult, Snapshot]:
    """Provision a disposable database, run the spec, evaluate rules, tear everything down."""
    fx = fixture if isinstance(fixture, Fixture) else find_fixture(fixture, settings.fixtures_dir)
    spec = spec or load_spec(fx.spec_path(variant))
    if only:
        keep = set(only)
        spec = spec.model_copy(update={"expectations": [e for e in spec.expectations if e.id in keep]})
    own = server is None
    srv = server or start_server(settings, backend=backend)
    emit = progress or (lambda e: None)
    try:
        emit({"stage": "provision", "message": f"Provisioning disposable {srv.kind} PostgreSQL {srv.version} for {fx.name}:{variant}"})
        with provision_fixture(srv, fx, variant, trusted=trusted) as fdb:
            snap = scan_fixture_snapshot(fdb, store_expressions=True)
            attach_migration_locations(snap, fx.sql_files(variant), fx.path)
            result = run_spec(fdb, spec, snapshot=snap, progress=progress, cancel=cancel, run_id=run_id or uuid.uuid4().hex[:12])
            result.info.environment_mode = "DISPOSABLE LAB"
            result.snapshot = snap.model_dump(mode="json")
            emit({"stage": "rules", "message": "Evaluating rules and building evidence"})
            findings = evaluate(snap, spec, result)
            result.findings = [f.model_dump(mode="json") for f in findings]
        emit({"stage": "teardown", "message": "Disposable database and roles removed"})
        return result, snap
    finally:
        if own:
            srv.stop()
