"""Runtime configuration, loaded from environment variables (never from files that could be committed)."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _list(name: str, default: str) -> list[str]:
    raw = os.environ.get(name, default)
    return [p.strip() for p in raw.split(",") if p.strip()]


def find_fixtures_dir() -> Path | None:
    env = os.environ.get("SENTINEL_FIXTURES_DIR")
    if env:
        return Path(env)
    here = Path(__file__).resolve().parent
    candidates = [
        here / "_bundled" / "fixtures",          # installed wheel
        here.parent.parent / "fixtures",         # repo checkout: backend/../fixtures
        Path.cwd() / "fixtures",
    ]
    for c in candidates:
        if c.is_dir():
            return c
    return None


def find_ui_dir() -> Path | None:
    env = os.environ.get("SENTINEL_UI_DIR")
    if env:
        return Path(env)
    here = Path(__file__).resolve().parent
    for c in (here / "_bundled" / "ui", here.parent.parent / "frontend" / "dist"):
        if (c / "index.html").is_file():
            return c
    return None


def find_pg_bin() -> Path | None:
    """Locate PostgreSQL server binaries (initdb/pg_ctl/postgres) for local disposable clusters."""
    env = os.environ.get("SENTINEL_PG_BIN")
    if env and (Path(env) / ("initdb.exe" if os.name == "nt" else "initdb")).exists():
        return Path(env)
    exe = shutil.which("initdb")
    if exe:
        return Path(exe).parent
    roots: list[Path] = []
    if os.name == "nt":
        for base in (os.environ.get("PROGRAMFILES", r"C:\Program Files"),):
            pg = Path(base) / "PostgreSQL"
            if pg.is_dir():
                roots += sorted((p / "bin" for p in pg.iterdir()), reverse=True)
    else:
        for base in ("/usr/lib/postgresql", "/opt/homebrew/opt", "/usr/local/opt"):
            b = Path(base)
            if b.is_dir():
                roots += sorted((p / "bin" for p in b.iterdir()), reverse=True)
        roots += [Path("/usr/pgsql-17/bin"), Path("/usr/local/pgsql/bin")]
    for r in roots:
        if (r / ("initdb.exe" if os.name == "nt" else "initdb")).exists():
            return r
    return None


@dataclass
class Settings:
    host: str = "127.0.0.1"
    port: int = 8787
    api_token: str | None = None
    data_dir: Path = field(default_factory=lambda: Path.home() / ".rls-sentinel")
    metadata_url: str | None = None
    fixtures_dir: Path | None = None
    ui_dir: Path | None = None
    fixture_backend: str = "auto"  # auto | local | docker | external
    fixture_admin_url: str | None = None
    fixture_disposable_ack: bool = False
    fixture_image: str = "postgres:17-alpine"
    pg_bin: Path | None = None
    allowed_targets: list[str] = field(default_factory=lambda: ["localhost", "127.0.0.0/8", "::1"])
    allowed_origins: list[str] = field(default_factory=list)
    retention_days: int = 90
    store_expressions: bool = True
    default_statement_timeout_ms: int = 1500
    max_parallelism: int = 4
    max_upload_bytes: int = 256 * 1024
    rate_limit_per_minute: int = 240
    job_workers: int = 2

    @property
    def resolved_metadata_url(self) -> str:
        if self.metadata_url:
            return self.metadata_url
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{(self.data_dir / 'sentinel.db').as_posix()}"

    @property
    def is_loopback_bind(self) -> bool:
        return self.host in {"127.0.0.1", "::1", "localhost"}


def load_settings() -> Settings:
    s = Settings(
        host=os.environ.get("SENTINEL_HOST", "127.0.0.1"),
        port=_int("SENTINEL_PORT", 8787),
        api_token=os.environ.get("SENTINEL_API_TOKEN") or None,
        data_dir=Path(os.environ.get("SENTINEL_DATA_DIR", str(Path.home() / ".rls-sentinel"))),
        metadata_url=os.environ.get("SENTINEL_METADATA_URL") or None,
        fixtures_dir=find_fixtures_dir(),
        ui_dir=find_ui_dir(),
        fixture_backend=os.environ.get("SENTINEL_FIXTURE_BACKEND", "auto").lower(),
        fixture_admin_url=os.environ.get("SENTINEL_FIXTURE_ADMIN_URL") or None,
        fixture_disposable_ack=_bool("SENTINEL_FIXTURE_DISPOSABLE", False),
        fixture_image=os.environ.get("SENTINEL_FIXTURE_IMAGE", "postgres:17-alpine"),
        pg_bin=find_pg_bin(),
        allowed_targets=_list("SENTINEL_ALLOWED_TARGETS", "localhost,127.0.0.0/8,::1"),
        allowed_origins=_list("SENTINEL_ALLOWED_ORIGINS", ""),
        retention_days=_int("SENTINEL_RETENTION_DAYS", 90),
        store_expressions=_bool("SENTINEL_STORE_EXPRESSIONS", True),
        default_statement_timeout_ms=_int("SENTINEL_STATEMENT_TIMEOUT_MS", 1500),
        max_parallelism=_int("SENTINEL_MAX_PARALLELISM", 4),
        max_upload_bytes=_int("SENTINEL_MAX_UPLOAD_BYTES", 256 * 1024),
        rate_limit_per_minute=_int("SENTINEL_RATE_LIMIT_PER_MINUTE", 240),
        job_workers=_int("SENTINEL_JOB_WORKERS", 2),
    )
    return s
