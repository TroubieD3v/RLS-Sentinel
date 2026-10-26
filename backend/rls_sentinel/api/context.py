"""Shared application context: settings, database, job manager, disposable-server holder and secret vault."""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field

from ..config import Settings
from ..errors import ConnectionFailed, NotFound, ProvisioningError
from ..harness.servers import DisposableServer, docker_available, start_server
from ..persistence.repo import Database
from .jobs import JobManager

log = logging.getLogger("rls_sentinel.api")


class SecretVault:
    """Session-only connection secrets. Held in process memory, never persisted, never returned by the API.

    A database-encrypted vault is deliberately NOT offered: without a configured external key-management system it
    would be a misleading claim. Operators who need persistence reference secrets from the server environment
    (``env:VARIABLE``), which is resolved at connection time.
    """

    def __init__(self) -> None:
        self._secrets: dict[str, str] = {}
        self._lock = threading.Lock()

    def put(self, cid: str, dsn: str) -> None:
        with self._lock:
            self._secrets[cid] = dsn

    def resolve(self, cid: str, secret_ref: str) -> str:
        if secret_ref.startswith("env:"):
            name = secret_ref[4:]
            val = os.environ.get(name)
            if not val:
                raise ConnectionFailed(f"Environment variable {name} is not set in the server process.")
            return val
        with self._lock:
            dsn = self._secrets.get(cid)
        if not dsn:
            raise NotFound("This connection's session secret is gone (the server restarted). Re-enter the connection string.")
        return dsn

    def drop(self, cid: str) -> None:
        with self._lock:
            self._secrets.pop(cid, None)


class ServerHolder:
    """Lazily provisions ONE disposable PostgreSQL server per process and reuses it for lab runs."""

    def __init__(self, settings: Settings, forbidden_urls: list[str]):
        self.settings = settings
        self.forbidden = forbidden_urls
        self._server: DisposableServer | None = None
        self._lock = threading.Lock()
        self.last_error: str | None = None

    def availability(self) -> dict[str, object]:
        s = self.settings
        backend = s.fixture_backend
        if self._server is not None:
            return {"available": True, "backend": self._server.kind, "detail": self._server.display, "running": True}
        if s.fixture_admin_url and s.fixture_disposable_ack:
            return {"available": True, "backend": "external", "detail": "operator-provisioned disposable server", "running": False}
        if backend in ("auto", "docker") and docker_available():
            return {"available": True, "backend": "docker", "detail": f"image {s.fixture_image}", "running": False}
        if backend in ("auto", "local") and s.pg_bin:
            return {"available": True, "backend": "local", "detail": f"local PostgreSQL binaries at {s.pg_bin}", "running": False}
        return {"available": False, "backend": backend,
                "detail": "No disposable PostgreSQL backend: install server binaries, start Docker, or set SENTINEL_FIXTURE_ADMIN_URL with SENTINEL_FIXTURE_DISPOSABLE=true.",
                "running": False}

    def get(self) -> DisposableServer:
        with self._lock:
            if self._server is None:
                try:
                    self._server = start_server(self.settings, forbidden_urls=self.forbidden)
                    self.last_error = None
                except Exception as exc:
                    self.last_error = str(exc)[:300]
                    raise
            return self._server

    def stop(self) -> None:
        with self._lock:
            if self._server is not None:
                self._server.stop()
                self._server = None


@dataclass
class AppContext:
    settings: Settings
    db: Database
    jobs: JobManager
    servers: ServerHolder
    vault: SecretVault = field(default_factory=SecretVault)

    def close(self) -> None:
        self.jobs.shutdown()
        try:
            self.servers.stop()
        except Exception as exc:  # pragma: no cover
            log.warning("server stop failed: %s", exc)
        self.db.dispose()


def build_context(settings: Settings, db: Database | None = None) -> AppContext:
    url = settings.resolved_metadata_url
    db = db or Database(url)
    db.init()
    db.fail_orphaned_jobs()
    jobs = JobManager(db, settings.job_workers)
    holder = ServerHolder(settings, [url])
    return AppContext(settings=settings, db=db, jobs=jobs, servers=holder)


__all__ = ["AppContext", "ProvisioningError", "SecretVault", "ServerHolder", "build_context"]
