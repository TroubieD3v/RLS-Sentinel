"""Bounded in-process job runner with cooperative cancellation and replayable SSE event logs.

Redis/RQ are not required for the single-node deployment this release targets: concurrency is bounded by a
fixed thread pool (``SENTINEL_JOB_WORKERS``) and every job is persisted in the metadata database. Jobs that were
in flight when the process died are marked failed at startup (see ``Database.fail_orphaned_jobs``).
"""

from __future__ import annotations

import logging
import threading
import time
import traceback
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from ..persistence.models import utcnow
from ..persistence.repo import Database
from ..redaction import redact_text

log = logging.getLogger("rls_sentinel.jobs")
TERMINAL = {"completed", "failed", "cancelled"}
MAX_EVENTS = 2000


@dataclass
class Job:
    id: str
    kind: str
    workspace_id: str | None
    status: str = "queued"
    events: list[dict[str, Any]] = field(default_factory=list)
    cancel: threading.Event = field(default_factory=threading.Event)
    cond: threading.Condition = field(default_factory=threading.Condition)
    result_ref: str | None = None
    error: str | None = None
    seq: int = 0

    def emit(self, type_: str, data: dict[str, Any]) -> None:
        with self.cond:
            self.seq += 1
            self.events.append({"seq": self.seq, "ts": time.time(), "type": type_, "data": data})
            if len(self.events) > MAX_EVENTS:
                del self.events[: len(self.events) - MAX_EVENTS]
            self.cond.notify_all()


class JobManager:
    def __init__(self, db: Database, workers: int = 2):
        self.db = db
        self.pool = ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="sentinel-job")
        self.jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def submit(self, kind: str, workspace_id: str | None, fn: Callable[[Job], str | None]) -> Job:
        jid = self.db.create_job(kind, workspace_id)
        job = Job(id=jid, kind=kind, workspace_id=workspace_id)
        with self._lock:
            self.jobs[jid] = job
        job.emit("queued", {"message": "Job queued"})

        def runner() -> None:
            if job.cancel.is_set():
                self._finish(job, "cancelled", None, None)
                return
            job.status = "running"
            self.db.update_job(jid, status="running", started_at=utcnow())
            job.emit("status", {"status": "running"})
            try:
                ref = fn(job)
                if job.cancel.is_set():
                    self._finish(job, "cancelled", ref, None)
                else:
                    self._finish(job, "completed", ref, None)
            except Exception as exc:
                msg = redact_text(f"{type(exc).__name__}: {exc}")[:400]
                log.warning("job %s failed: %s", jid, msg)
                log.debug("traceback: %s", redact_text(traceback.format_exc()))
                self._finish(job, "cancelled" if job.cancel.is_set() else "failed", None, msg)

        self.pool.submit(runner)
        return job

    def _finish(self, job: Job, status: str, ref: str | None, error: str | None) -> None:
        job.status, job.result_ref, job.error = status, ref, error
        self.db.update_job(job.id, status=status, finished_at=utcnow(), result_ref=ref, error=error)
        job.emit(status, {"status": status, "error": error, "result_ref": ref})

    def get(self, jid: str) -> Job | None:
        return self.jobs.get(jid)

    def cancel(self, jid: str) -> bool:
        job = self.jobs.get(jid)
        if not job or job.status in TERMINAL:
            return False
        job.cancel.set()
        job.emit("cancel_requested", {"message": "Cancellation requested; the run stops at the next safe point"})
        return True

    def stream(self, jid: str, after: int = 0, heartbeat: float = 15.0, idle_timeout: float = 3600.0) -> Iterator[str]:
        """Server-sent events with heartbeat comments; resumable with ``after`` (Last-Event-ID)."""
        job = self.jobs.get(jid)
        if job is None:
            # job finished before this process started (or unknown): emit its persisted state once
            try:
                row = self.db.get_job(jid)
            except Exception:
                yield "event: error\ndata: {\"detail\": \"unknown job\"}\n\n"
                return
            import json

            yield f"id: 1\nevent: {row['status']}\ndata: {json.dumps({'status': row['status'], 'error': row['error'], 'result_ref': row['result_ref']})}\n\n"
            return
        import json

        cursor = after
        started = time.monotonic()
        yield "retry: 3000\n\n"
        while True:
            with job.cond:
                pending = [e for e in job.events if e["seq"] > cursor]
                if not pending and job.status not in TERMINAL:
                    job.cond.wait(timeout=heartbeat)
                    pending = [e for e in job.events if e["seq"] > cursor]
            if pending:
                for e in pending:
                    cursor = e["seq"]
                    yield f"id: {e['seq']}\nevent: {e['type']}\ndata: {json.dumps(e['data'], default=str)}\n\n"
                continue
            if job.status in TERMINAL:
                return
            if time.monotonic() - started > idle_timeout:
                return
            yield f": heartbeat {int(time.time())}\n\n"

    def shutdown(self) -> None:
        for j in self.jobs.values():
            j.cancel.set()
        self.pool.shutdown(wait=False, cancel_futures=True)
