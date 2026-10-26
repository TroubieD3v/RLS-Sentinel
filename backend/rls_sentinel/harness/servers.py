"""Disposable PostgreSQL servers for the behavioral lab.

Three backends:
  * ``local``    - a throw-away cluster created with the locally installed ``initdb``/``postgres``
                   binaries (loopback only, random port, random password, deleted on stop).
  * ``docker``   - a hardened throw-away container (dropped capabilities, no-new-privileges,
                   read-only root, tmpfs data dir, CPU/memory/pids limits, loopback-published port,
                   no host mounts, no Docker socket inside).
  * ``external`` - an operator-provisioned server (e.g. the ``fixture-db`` compose service). Only
                   accepted with an explicit disposable acknowledgement and only if it holds no
                   databases other than ``postgres``/``template*``/``sentinel_*``.

Docker isolation is not a perfect security boundary (see docs/threat-model.md).
"""

from __future__ import annotations

import atexit
import contextlib
import logging
import os
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path

import psycopg
from psycopg import sql

from ..config import Settings
from ..errors import ProvisioningError, UnsafeOperation

log = logging.getLogger("rls_sentinel.servers")

ADMIN_ROLE = "sentinel_admin"
ADVISORY_LOCK_KEY = 727274_0001
_LIVE: list[DisposableServer] = []
_LIVE_LOCK = threading.Lock()


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        code = ctypes.c_ulong()
        ok = k32.GetExitCodeProcess(h, ctypes.byref(code))
        k32.CloseHandle(h)
        return bool(ok) and code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def reap_orphan_clusters(pg_bin: Path) -> int:
    """Stop and delete throw-away clusters whose creating process died without cleaning up (e.g. it was killed)."""
    exe = ".exe" if os.name == "nt" else ""
    reaped = 0
    for d in Path(tempfile.gettempdir()).glob("sentinel-pg-*"):
        marker = d / "owner.pid"
        try:
            owner = int(marker.read_text().strip())
        except (OSError, ValueError):
            continue
        if _pid_alive(owner):
            continue
        with contextlib.suppress(Exception):
            subprocess.run([str(pg_bin / f"pg_ctl{exe}"), "stop", "-D", str(d / "data"), "-m", "immediate", "-w", "-t", "15"],  # noqa: S603
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, timeout=30, check=False)
        for _ in range(8):
            try:
                shutil.rmtree(d)
                reaped += 1
                break
            except OSError:
                time.sleep(0.4)
    return reaped


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_ready(dsn: str, *, timeout: float, alive=lambda: True, what: str = "PostgreSQL") -> None:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        if not alive():
            raise ProvisioningError(f"{what} exited during startup.")
        try:
            with psycopg.connect(dsn, connect_timeout=2) as c:
                c.execute("SELECT 1")
            return
        except psycopg.Error as exc:
            last = exc
            time.sleep(0.3)
    raise ProvisioningError(f"{what} did not become ready within {timeout:.0f}s: {str(last)[:200]}")


class DisposableServer:
    kind = "abstract"
    host = "127.0.0.1"
    port = 0
    _password = ""
    version_num = 0
    version = ""
    owned = True  # whether stop() destroys the server

    def admin_dsn(self, dbname: str = "postgres") -> str:
        return f"postgresql://{ADMIN_ROLE}:{self._password}@{self.host}:{self.port}/{dbname}"

    def stop(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def _probe_version(self) -> None:
        with psycopg.connect(self.admin_dsn(), connect_timeout=5) as c:
            row = c.execute("SELECT current_setting('server_version_num')::int, current_setting('server_version')").fetchone()
            assert row is not None
            self.version_num, self.version = int(row[0]), str(row[1])
        _register(self)

    @property
    def major(self) -> int:
        return self.version_num // 10000

    @property
    def display(self) -> str:
        return f"{self.kind} · PostgreSQL {self.version} · {self.host}:{self.port}"


def _register(s: DisposableServer) -> None:
    with _LIVE_LOCK:
        if s not in _LIVE:
            _LIVE.append(s)


def stop_all_servers() -> None:
    with _LIVE_LOCK:
        servers = list(_LIVE)
        _LIVE.clear()
    for s in servers:
        with contextlib.suppress(Exception):
            s.stop()


atexit.register(stop_all_servers)


# ----------------------------------------------------------------------------- local
class LocalClusterServer(DisposableServer):
    kind = "local"

    def __init__(self, pg_bin: Path, *, startup_timeout: float = 60.0):
        self.pg_bin = pg_bin
        exe = ".exe" if os.name == "nt" else ""
        self._initdb = pg_bin / f"initdb{exe}"
        self._postgres = pg_bin / f"postgres{exe}"
        self._pg_ctl = pg_bin / f"pg_ctl{exe}"
        with contextlib.suppress(Exception):
            reap_orphan_clusters(pg_bin)
        self.root = Path(tempfile.mkdtemp(prefix="sentinel-pg-"))
        (self.root / "owner.pid").write_text(str(os.getpid()))
        self.data = self.root / "data"
        self._password = secrets.token_urlsafe(24)
        self.port = _free_port()
        self._proc: subprocess.Popen | None = None
        self._stopped = False
        self._start(startup_timeout)

    def _start(self, timeout: float) -> None:
        pwfile = self.root / "pw"
        pwfile.write_text(self._password)
        try:
            subprocess.run(  # noqa: S603
                [str(self._initdb), "-D", str(self.data), "-U", ADMIN_ROLE, "-A", "scram-sha-256",
                 f"--pwfile={pwfile}", "--locale=C", "-E", "UTF8", "--no-sync"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, timeout=180,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            self._cleanup_files()
            detail = getattr(exc, "stderr", b"") or b""
            raise ProvisioningError(f"initdb failed: {detail.decode(errors='replace')[:300] or exc}") from exc
        finally:
            with contextlib.suppress(OSError):
                pwfile.unlink()
        args = [
            str(self._postgres), "-D", str(self.data),
            "-c", f"port={self.port}", "-c", "listen_addresses=127.0.0.1",
            "-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off",
            "-c", "max_connections=60", "-c", "shared_buffers=32MB", "-c", "lc_messages=C",
            "-c", "log_min_messages=warning", "-c", "password_encryption=scram-sha-256",
        ]
        if os.name != "nt":
            args += ["-c", f"unix_socket_directories={self.root}"]
        logf = open(self.root / "postgres.log", "wb")  # noqa: SIM115 - handed to Popen
        kwargs: dict = {}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        self._proc = subprocess.Popen(  # noqa: S603
            args, stdout=logf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, **kwargs)
        try:
            _wait_ready(self.admin_dsn(), timeout=timeout, alive=lambda: self._proc is not None and self._proc.poll() is None)
            self._probe_version()
        except Exception:
            self.stop()
            raise

    def _cleanup_files(self) -> None:
        for _ in range(10):
            try:
                shutil.rmtree(self.root)
                return
            except FileNotFoundError:
                return
            except OSError:
                time.sleep(0.4)
        log.warning("Could not fully remove %s", self.root)

    def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        with _LIVE_LOCK:
            if self in _LIVE:
                _LIVE.remove(self)
        if self._proc is not None and self._proc.poll() is None:
            with contextlib.suppress(Exception):
                subprocess.run(  # noqa: S603
                    [str(self._pg_ctl), "stop", "-D", str(self.data), "-m", "immediate", "-w", "-t", "20"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, timeout=40, check=False)
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                with contextlib.suppress(Exception):
                    self._proc.wait(timeout=10)
        self._cleanup_files()

    @property
    def cleaned_up(self) -> bool:
        return not self.root.exists() and (self._proc is None or self._proc.poll() is not None)


# ----------------------------------------------------------------------------- docker
def docker_available(*, refresh: bool = False) -> bool:
    global _DOCKER_OK
    if _DOCKER_OK is not None and not refresh:
        return _DOCKER_OK
    exe = shutil.which("docker")
    ok = False
    if exe:
        try:
            r = subprocess.run([exe, "version", "--format", "{{.Server.Version}}"], capture_output=True, timeout=12, check=False)  # noqa: S603
            ok = r.returncode == 0 and bool(r.stdout.strip())
        except (subprocess.TimeoutExpired, OSError):
            ok = False
    _DOCKER_OK = ok
    return ok


_DOCKER_OK: bool | None = None


class DockerServer(DisposableServer):
    kind = "docker"

    def __init__(self, image: str = "postgres:17-alpine", *, startup_timeout: float = 120.0):
        self.image = image
        self.container = f"sentinel-fixture-{uuid.uuid4().hex[:10]}"
        self._password = secrets.token_urlsafe(24)
        self._stopped = False
        self._docker = shutil.which("docker") or "docker"
        cmd = [
            self._docker, "run", "-d", "--rm", "--name", self.container,
            "--label", "rls-sentinel=disposable",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "256", "--memory", "768m", "--cpus", "1.5",
            "--read-only", "--tmpfs", "/tmp:rw,size=64m",  # noqa: S108
            "--tmpfs", "/var/run/postgresql:rw,mode=1777",
            "--tmpfs", "/pgdata:rw,mode=1777,size=512m",
            "--user", "postgres",
            "-e", f"POSTGRES_USER={ADMIN_ROLE}", "-e", f"POSTGRES_PASSWORD={self._password}",
            "-e", "PGDATA=/pgdata/data", "-e", "POSTGRES_INITDB_ARGS=--locale=C -E UTF8",
            "-p", "127.0.0.1::5432",
            image,
            "-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off",
            "-c", "max_connections=60", "-c", "shared_buffers=32MB", "-c", "lc_messages=C",
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)  # noqa: S603
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise ProvisioningError(f"docker run failed: {exc}") from exc
        if r.returncode != 0:
            raise ProvisioningError(f"docker run failed: {r.stderr.strip()[:300]}")
        try:
            out = subprocess.run([self._docker, "port", self.container, "5432/tcp"], capture_output=True, text=True, timeout=20, check=True).stdout  # noqa: S603
            self.port = int(out.strip().splitlines()[0].rsplit(":", 1)[1])
            _wait_ready(self.admin_dsn(), timeout=startup_timeout,
                        alive=self._is_running, what=f"container {self.container}")
            self._probe_version()
        except Exception:
            self.stop()
            raise

    def _is_running(self) -> bool:
        r = subprocess.run([self._docker, "inspect", "-f", "{{.State.Running}}", self.container], capture_output=True, text=True, timeout=15, check=False)  # noqa: S603
        return r.stdout.strip() == "true"

    def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        with _LIVE_LOCK:
            if self in _LIVE:
                _LIVE.remove(self)
        with contextlib.suppress(Exception):
            subprocess.run([self._docker, "rm", "-f", self.container], capture_output=True, timeout=60, check=False)  # noqa: S603

    @property
    def cleaned_up(self) -> bool:
        r = subprocess.run([self._docker, "ps", "-a", "-q", "--filter", f"name={self.container}"], capture_output=True, text=True, timeout=20, check=False)  # noqa: S603
        return not r.stdout.strip()


# ----------------------------------------------------------------------------- external
class ExternalServer(DisposableServer):
    """Operator-provisioned disposable server (e.g. compose ``fixture-db``)."""

    kind = "external"
    owned = False

    def __init__(self, admin_url: str, *, acknowledged: bool, forbidden_urls: list[str] | None = None):
        if not acknowledged:
            raise UnsafeOperation(
                "SENTINEL_FIXTURE_ADMIN_URL is set but SENTINEL_FIXTURE_DISPOSABLE=true was not provided. "
                "Mutating tests only run on servers explicitly acknowledged as disposable.")
        from psycopg import conninfo

        params = conninfo.conninfo_to_dict(admin_url)
        for bad in forbidden_urls or []:
            if not bad or bad.startswith("sqlite"):
                continue
            try:
                other = conninfo.conninfo_to_dict(bad)
            except Exception:  # noqa: S112
                continue
            if (other.get("host"), other.get("port")) == (params.get("host"), params.get("port")):
                raise UnsafeOperation("The fixture server must not be the same server as the metadata or a source database.")
        self.host = str(params.get("host") or "127.0.0.1")
        self.port = int(params.get("port") or 5432)
        self._user = str(params.get("user") or ADMIN_ROLE)
        self._password = str(params.get("password") or "")
        self._verify()
        self._probe_version()

    def admin_dsn(self, dbname: str = "postgres") -> str:
        from urllib.parse import quote

        return f"postgresql://{quote(self._user)}:{quote(self._password)}@{self.host}:{self.port}/{dbname}"

    def _verify(self) -> None:
        try:
            with psycopg.connect(self.admin_dsn(), connect_timeout=8) as c:
                if c.execute("SELECT current_setting('is_superuser')").fetchone()[0] != "on":  # type: ignore[index]
                    raise UnsafeOperation("The fixture admin account must be a superuser of the disposable server.")
                extra = [r[0] for r in c.execute(
                    "SELECT datname FROM pg_database WHERE datname NOT IN ('postgres','template0','template1') "
                    "AND datname NOT LIKE 'sentinel\\_%'").fetchall()]
        except psycopg.OperationalError as exc:
            raise ProvisioningError(f"Cannot reach the fixture server: {str(exc)[:200]}") from exc
        if extra:
            raise UnsafeOperation(
                "Refusing to use a server that holds non-sentinel databases as a disposable fixture server: "
                f"{extra[:5]}. Point SENTINEL_FIXTURE_ADMIN_URL at a dedicated disposable instance.")

    def stop(self) -> None:
        with _LIVE_LOCK:
            if self in _LIVE:
                _LIVE.remove(self)


# ----------------------------------------------------------------------------- factory
def start_server(settings: Settings, *, backend: str | None = None, pg_image: str | None = None,
                 forbidden_urls: list[str] | None = None) -> DisposableServer:
    backend = (backend or settings.fixture_backend or "auto").lower()
    if backend == "auto":
        if settings.fixture_admin_url:
            backend = "external"
        elif docker_available():
            backend = "docker"
        elif settings.pg_bin:
            backend = "local"
    if backend == "external":
        if not settings.fixture_admin_url:
            raise ProvisioningError("SENTINEL_FIXTURE_ADMIN_URL is not set.")
        return ExternalServer(settings.fixture_admin_url, acknowledged=settings.fixture_disposable_ack,
                              forbidden_urls=forbidden_urls)
    if backend == "docker":
        if not docker_available():
            raise ProvisioningError("Docker backend requested but the Docker daemon is not reachable.")
        return DockerServer(pg_image or settings.fixture_image)
    if backend == "local" and settings.pg_bin:
        return LocalClusterServer(settings.pg_bin)
    raise ProvisioningError(
        "No disposable PostgreSQL backend is available. Install PostgreSQL server binaries (set SENTINEL_PG_BIN), "
        "start Docker, or provide SENTINEL_FIXTURE_ADMIN_URL with SENTINEL_FIXTURE_DISPOSABLE=true.")


def quote_ident(name: str) -> sql.Identifier:
    return sql.Identifier(name)
