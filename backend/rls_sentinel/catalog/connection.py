"""Connection factory for the *inspected source* database.

The source connection is hardened at the session level:
  * ``default_transaction_read_only=on`` and an explicit READ ONLY transaction,
  * short ``statement_timeout`` / ``lock_timeout`` / ``idle_in_transaction_session_timeout``,
  * target host validated against the allowlist and the resolved address pinned (``hostaddr``).

Credentials are never logged. ``CatalogSession`` exposes only named queries from :mod:`queries`.
"""

from __future__ import annotations

import logging
from typing import Any

import psycopg
from psycopg import conninfo
from psycopg.rows import dict_row

from ..auth.netguard import resolve_allowed
from ..errors import ConnectionFailed, ConnectionRefusedByPolicy
from ..redaction import redact_text
from .queries import Q

log = logging.getLogger("rls_sentinel.catalog")


def prepare_conninfo(
    dsn: str,
    *,
    allowed_targets: list[str] | None,
    options: str,
    application_name: str,
    connect_timeout: int = 8,
) -> dict[str, Any]:
    try:
        params = conninfo.conninfo_to_dict(dsn)
    except psycopg.ProgrammingError as exc:
        raise ConnectionFailed("Invalid connection string.") from exc
    host = str(params.get("host") or "")
    if "," in host:
        raise ConnectionRefusedByPolicy("Multi-host connection strings are not accepted.")
    if host.startswith("/"):
        raise ConnectionRefusedByPolicy("Unix-socket targets are not accepted.")
    port = int(params.get("port") or 5432)
    if allowed_targets is not None:
        target = resolve_allowed(host or "localhost", port, allowed_targets)
        params["host"] = target.host
        params["hostaddr"] = target.hostaddr
    for k in ("service", "passfile", "sslkey", "sslcert", "sslrootcert"):
        # Do not let a DSN make the server read arbitrary local files.
        params.pop(k, None)
    params["options"] = options
    params["application_name"] = application_name
    params["connect_timeout"] = connect_timeout
    return params


class CatalogSession:
    """Read-only catalog access. The only way to run SQL is :meth:`fetch` with a registered query name."""

    def __init__(self, conn: psycopg.Connection):
        self._conn = conn

    def fetch(self, name: str, **params: Any) -> list[dict[str, Any]]:
        sql_text = Q[name]
        with self._conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql_text, params)
            return list(cur.fetchall())

    def savepoint(self):
        return self._conn.transaction()

    def close(self) -> None:
        try:
            self._conn.rollback()
        finally:
            self._conn.close()

    def __enter__(self) -> CatalogSession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def open_catalog_session(
    dsn: str,
    *,
    allowed_targets: list[str] | None = None,
    statement_timeout_ms: int = 8000,
) -> CatalogSession:
    options = (
        f"-c default_transaction_read_only=on -c statement_timeout={int(statement_timeout_ms)} "
        "-c lock_timeout=2000 -c idle_in_transaction_session_timeout=60000"
    )
    params = prepare_conninfo(
        dsn, allowed_targets=allowed_targets, options=options, application_name="rls-sentinel-catalog"
    )
    try:
        conn = psycopg.connect(**params, autocommit=False)
        conn.read_only = True
    except psycopg.OperationalError as exc:
        raise ConnectionFailed(f"Could not connect: {redact_text(str(exc).strip())[:300]}") from exc
    return CatalogSession(conn)
