"""Fixture packages: schema + seed + expectations, and their provisioning into a disposable server."""

from __future__ import annotations

import contextlib
import hashlib
import logging
import re
import secrets
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import psycopg
import yaml
from pglast import ast, parse_sql
from pglast.enums import ObjectType
from psycopg import sql

from ..errors import NotFound, ProvisioningError, SpecError
from .servers import ADVISORY_LOCK_KEY, DisposableServer

log = logging.getLogger("rls_sentinel.fixtures")

HARNESS_ROLE = "sentinel_harness"
VARIANTS = ("vulnerable", "secure")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,62}$")


# ------------------------------------------------------------------------------- model
@dataclass
class Fixture:
    name: str
    title: str
    description: str
    path: Path
    variants: dict[str, list[Path]]
    spec_paths: dict[str, Path]
    roles: list[str]
    expected: dict[str, dict[str, Any]] = field(default_factory=dict)
    requires_extensions: list[str] = field(default_factory=list)
    min_pg_major: int = 15
    tags: list[str] = field(default_factory=list)
    bundled: bool = False

    def sql_files(self, variant: str) -> list[Path]:
        if variant not in self.variants:
            raise NotFound(f"Fixture '{self.name}' has no variant '{variant}'.")
        return self.variants[variant]

    def spec_path(self, variant: str) -> Path:
        return self.spec_paths.get(variant) or self.spec_paths["*"]

    def fingerprint(self, variant: str) -> str:
        h = hashlib.sha256()
        h.update(self.name.encode())
        h.update(variant.encode())
        for p in self.sql_files(variant):
            h.update(p.name.encode())
            h.update(p.read_bytes())
        return "sha256:" + h.hexdigest()

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name, "title": self.title, "description": self.description,
            "variants": list(self.variants), "roles": self.roles, "tags": self.tags,
            "min_pg_major": self.min_pg_major, "requires_extensions": self.requires_extensions,
        }


def load_fixture(path: str | Path, *, bundled: bool = False) -> Fixture:
    root = Path(path)
    manifest = root / "fixture.yaml"
    if not manifest.is_file():
        raise NotFound(f"No fixture.yaml in {root}.")
    data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
    name = str(data.get("name", root.name))
    if not _NAME_RE.match(name):
        raise SpecError(f"Invalid fixture name '{name}'.")
    variants: dict[str, list[Path]] = {}
    for vname, files in (data.get("variants") or {}).items():
        if vname not in VARIANTS:
            raise SpecError(f"Unknown variant '{vname}' (expected one of {VARIANTS}).")
        paths = []
        for f in files:
            p = (root / f).resolve()
            if root.resolve() not in p.parents:
                raise SpecError(f"Fixture file escapes the fixture directory: {f}")
            if not p.is_file():
                raise NotFound(f"Fixture file missing: {f}")
            paths.append(p)
        variants[vname] = paths
    specs: dict[str, Path] = {}
    spec_field = data.get("spec")
    if isinstance(spec_field, str):
        specs["*"] = (root / spec_field).resolve()
    elif isinstance(spec_field, dict):
        for k, v in spec_field.items():
            specs[k] = (root / v).resolve()
    if "*" not in specs and not all(v in specs for v in variants):
        raise SpecError("Fixture must declare 'spec' for every variant (or a single default spec).")
    for p in specs.values():
        if root.resolve() not in p.parents or not p.is_file():
            raise NotFound(f"Fixture spec missing or outside the fixture: {p}")
    return Fixture(
        name=name, title=str(data.get("title", name)), description=str(data.get("description", "")).strip(),
        path=root, variants=variants, spec_paths=specs, roles=list(data.get("roles", [])),
        expected=data.get("expected_outcomes", {}) or {}, requires_extensions=list(data.get("requires_extensions", [])),
        min_pg_major=int(data.get("min_pg_major", 15)), tags=list(data.get("tags", [])), bundled=bundled,
    )


def discover_fixtures(root: Path | None, *, bundled: bool = True) -> list[Fixture]:
    if root is None or not root.is_dir():
        return []
    out = []
    preferred = ["multi-tenant-saas", "policy-precedence", "saas-auth-context", "external-benchmark"]
    for d in sorted(root.iterdir(), key=lambda p: (preferred.index(p.name) if p.name in preferred else 99, p.name)):
        if (d / "fixture.yaml").is_file():
            try:
                out.append(load_fixture(d, bundled=bundled))
            except Exception as exc:
                log.warning("Skipping invalid fixture %s: %s", d.name, exc)
    return out


def find_fixture(name_or_path: str, root: Path | None) -> Fixture:
    p = Path(name_or_path)
    if p.is_dir() and (p / "fixture.yaml").is_file():
        return load_fixture(p)
    for f in discover_fixtures(root):
        if f.name == name_or_path:
            return f
    raise NotFound(f"Fixture '{name_or_path}' not found.")


# --------------------------------------------------------------------------------- lint
_FORBIDDEN_LANGS = {"c", "internal", "plpythonu", "plpython3u", "plperlu", "pltclu", "plsh"}


def lint_sql_script(text: str) -> list[str]:
    """AST-based safety lint for fixture scripts. Returns a list of problems (empty = ok)."""
    problems: list[str] = []
    try:
        stmts = parse_sql(text)
    except Exception as exc:
        return [f"SQL does not parse: {str(exc)[:160]}"]
    for raw in stmts:
        s = raw.stmt
        if isinstance(s, ast.CopyStmt) and (s.is_program or s.filename):
            problems.append("COPY with PROGRAM/file is not allowed in fixtures.")
        elif isinstance(s, ast.VariableSetStmt) and s.name and s.name.lower() in ("session_authorization",):
            problems.append("SET SESSION AUTHORIZATION is not allowed in fixtures.")
        elif isinstance(s, ast.AlterSystemStmt):
            problems.append("ALTER SYSTEM is not allowed in fixtures.")
        elif isinstance(s, ast.CreateTableSpaceStmt):
            problems.append("CREATE TABLESPACE is not allowed in fixtures.")
        elif isinstance(s, ast.CreateFunctionStmt):
            for opt in s.options or []:
                if opt.defname == "language" and str(opt.arg.sval).lower() in _FORBIDDEN_LANGS:
                    problems.append(f"Function language '{opt.arg.sval}' is not allowed in fixtures.")
        elif isinstance(s, ast.CreateFdwStmt | ast.CreateForeignServerStmt | ast.CreateForeignTableStmt):
            problems.append("Foreign data wrappers are not allowed in fixtures.")
        elif isinstance(s, ast.DropdbStmt | ast.CreatedbStmt):
            problems.append("Database-level DDL is not allowed in fixtures.")
    return problems


_DRAFT_ALLOWED = (
    ast.CreatePolicyStmt, ast.AlterPolicyStmt, ast.GrantStmt, ast.AlterTableStmt, ast.ViewStmt,
    ast.CreateFunctionStmt, ast.AlterFunctionStmt, ast.AlterOwnerStmt, ast.RenameStmt, ast.CreateStmt, ast.IndexStmt,
)


def lint_draft_sql(text: str) -> list[str]:
    """Allow-list for What-if draft SQL: policy / RLS / grant / view / function DDL only."""
    problems: list[str] = []
    try:
        stmts = parse_sql(text)
    except Exception as exc:
        return [f"SQL does not parse: {str(exc)[:200]}"]
    if not stmts:
        return ["Draft SQL is empty."]
    if len(stmts) > 40:
        return ["Draft SQL has more than 40 statements."]
    for raw in stmts:
        s = raw.stmt
        name = type(s).__name__
        if isinstance(s, ast.DropStmt):
            if s.removeType not in (ObjectType.OBJECT_POLICY, ObjectType.OBJECT_VIEW, ObjectType.OBJECT_FUNCTION):
                problems.append("DROP is only allowed for POLICY, VIEW and FUNCTION in draft SQL.")
            continue
        if not isinstance(s, _DRAFT_ALLOWED):
            problems.append(f"{name} is not permitted in draft SQL (policy/RLS/grant/view/function DDL only).")
            continue
        if isinstance(s, ast.CreateFunctionStmt):
            for opt in s.options or []:
                if opt.defname == "language" and str(opt.arg.sval).lower() not in ("sql", "plpgsql"):
                    problems.append(f"Function language '{opt.arg.sval}' is not allowed in draft SQL.")
        if isinstance(s, ast.AlterTableStmt):
            continue
    return problems


# ------------------------------------------------------------------------- provisioning
@dataclass
class FixtureDatabase:
    server: DisposableServer
    fixture: Fixture
    variant: str
    dbname: str
    harness_password: str
    created_roles: list[str]
    fingerprint: str
    _lock_conn: psycopg.Connection | None
    _torn_down: bool = False

    @property
    def admin_dsn(self) -> str:
        return self.server.admin_dsn(self.dbname)

    @property
    def harness_dsn(self) -> str:
        base = self.server.admin_dsn(self.dbname)
        # swap credentials
        prefix = base.split("@", 1)[1]
        return f"postgresql://{HARNESS_ROLE}:{self.harness_password}@{prefix}"

    def admin_connect(self, **kw: Any) -> psycopg.Connection:
        return psycopg.connect(self.admin_dsn, options="-c lc_messages=C", **kw)

    def grant_harness(self, roles: list[str]) -> None:
        with self.admin_connect(autocommit=True) as c:
            for r in sorted(set(roles)):
                c.execute(sql.SQL("GRANT {} TO {}").format(sql.Identifier(r), sql.Identifier(HARNESS_ROLE)))

    def teardown(self) -> None:
        if self._torn_down:
            return
        self._torn_down = True
        try:
            with psycopg.connect(self.server.admin_dsn("postgres"), autocommit=True, connect_timeout=10) as c:
                c.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(self.dbname)))
                for r in [HARNESS_ROLE, *self.created_roles]:
                    with contextlib.suppress(psycopg.Error):
                        c.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(r)))
        except psycopg.Error as exc:
            log.warning("Fixture teardown problem: %s", str(exc)[:200])
        finally:
            if self._lock_conn is not None:
                with contextlib.suppress(psycopg.Error):
                    self._lock_conn.close()

    def __enter__(self) -> FixtureDatabase:
        return self

    def __exit__(self, *exc: object) -> None:
        self.teardown()


def _acquire_lock(server: DisposableServer, timeout: float) -> psycopg.Connection:
    conn = psycopg.connect(server.admin_dsn("postgres"), autocommit=True, connect_timeout=10)
    deadline = time.monotonic() + timeout
    while True:
        got = conn.execute("SELECT pg_try_advisory_lock(%s)", (ADVISORY_LOCK_KEY,)).fetchone()[0]  # type: ignore[index]
        if got:
            return conn
        if time.monotonic() > deadline:
            conn.close()
            raise ProvisioningError("Timed out waiting for another run to release the disposable server.")
        time.sleep(0.5)


def provision_fixture(
    server: DisposableServer,
    fixture: Fixture,
    variant: str,
    *,
    lock_timeout: float = 180.0,
    trusted: bool | None = None,
) -> FixtureDatabase:
    """Create an isolated database + roles for the fixture. Caller must ``teardown()``."""
    if variant not in fixture.variants:
        raise NotFound(f"Fixture '{fixture.name}' has no variant '{variant}'.")
    if server.major < fixture.min_pg_major:
        raise ProvisioningError(f"Fixture requires PostgreSQL >= {fixture.min_pg_major}, server is {server.major}.")
    trusted = fixture.bundled if trusted is None else trusted
    scripts: list[tuple[Path, str]] = []
    for p in fixture.sql_files(variant):
        text = p.read_text(encoding="utf-8")
        problems = lint_sql_script(text)
        if problems:
            raise ProvisioningError(f"Fixture script {p.name} failed the safety lint: {problems[0]}")
        scripts.append((p, text))

    lock_conn = _acquire_lock(server, lock_timeout)
    dbname = f"sentinel_{uuid.uuid4().hex[:12]}"
    password = secrets.token_urlsafe(24)
    created: list[str] = []
    try:
        with psycopg.connect(server.admin_dsn("postgres"), autocommit=True) as c:
            # Remove leftovers from interrupted runs (we hold the exclusive lease).
            for (stale,) in c.execute("SELECT datname FROM pg_database WHERE datname LIKE 'sentinel\\_%'").fetchall():
                c.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(stale)))
            for r in [HARNESS_ROLE, *fixture.roles]:
                c.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(r)))
            before = {r[0] for r in c.execute("SELECT rolname FROM pg_roles").fetchall()}
            c.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0 ENCODING 'UTF8'").format(sql.Identifier(dbname)))
            c.execute(sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(sql.Identifier(dbname)))
            # NOINHERIT: the harness holds no privileges of its own; it only SET ROLEs into actor roles.
            c.execute(sql.SQL(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD {}"
            ).format(sql.Identifier(HARNESS_ROLE), sql.Literal(password)))
            c.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(sql.Identifier(dbname), sql.Identifier(HARNESS_ROLE)))
            # Stable English messages help diagnostics; classification does not depend on message text alone.
            with contextlib.suppress(psycopg.Error):
                c.execute(sql.SQL("ALTER ROLE {} SET lc_messages = 'C'").format(sql.Identifier(HARNESS_ROLE)))
        with psycopg.connect(server.admin_dsn(dbname), autocommit=True, options="-c lc_messages=C") as c:
            for ext in fixture.requires_extensions:
                c.execute(sql.SQL("CREATE EXTENSION IF NOT EXISTS {}").format(sql.Identifier(ext)))
            for p, text in scripts:
                try:
                    c.execute(text)
                except psycopg.Error as exc:
                    raise ProvisioningError(f"Fixture script {p.name} failed: {str(exc).splitlines()[0][:240]}") from exc
        with psycopg.connect(server.admin_dsn("postgres"), autocommit=True) as c:
            after = {r[0] for r in c.execute("SELECT rolname FROM pg_roles").fetchall()}
            created = sorted(r for r in after - before if not r.startswith("pg_") and r != HARNESS_ROLE)
            # Harness role needs to read the catalog only; make sure PUBLIC-connect on the new DB is closed.
        db = FixtureDatabase(server=server, fixture=fixture, variant=variant, dbname=dbname,
                             harness_password=password, created_roles=created,
                             fingerprint=fixture.fingerprint(variant), _lock_conn=lock_conn)
        return db
    except Exception:
        # best-effort cleanup then release the lease
        with contextlib.suppress(Exception), psycopg.connect(server.admin_dsn("postgres"), autocommit=True) as c:
            c.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(dbname)))
            for r in [HARNESS_ROLE, *fixture.roles]:
                c.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(r)))
        with contextlib.suppress(Exception):
            lock_conn.close()
        raise


def leftovers(server: DisposableServer) -> dict[str, list[str]]:
    """Databases/roles that should not exist after teardown (used by cleanup tests)."""
    with psycopg.connect(server.admin_dsn("postgres"), autocommit=True) as c:
        dbs = [r[0] for r in c.execute("SELECT datname FROM pg_database WHERE datname LIKE 'sentinel\\_%'").fetchall()]
        roles = [r[0] for r in c.execute(
            "SELECT rolname FROM pg_roles WHERE rolname !~ '^pg_' AND rolname <> 'sentinel_admin'").fetchall()]
    return {"databases": dbs, "roles": roles}
