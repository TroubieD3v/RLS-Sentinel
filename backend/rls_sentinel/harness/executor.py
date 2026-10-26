"""Raw behavioral observation: run one generated statement as one actor and record what PostgreSQL did.

Execution model for every case:
    BEGIN;  SET LOCAL ROLE <actor role>;  <probes>;  <statement in a savepoint>;  ROLLBACK;
The harness login role is a plain NOSUPERUSER/NOBYPASSRLS/NOINHERIT role that is a member of each
actor role, so ``SET ROLE`` is authorized by genuine role membership. ``session_user`` (harness) and
``current_user`` (actor) are both recorded.
"""

from __future__ import annotations

import contextlib
import json
import logging
import threading
import time
from collections.abc import Callable
from typing import Any

import psycopg
from psycopg import errors as pgerr
from psycopg import sql

from ..expectations.models import Actor
from ..redaction import mask_identifier, redact_text
from .ops import OpPlan, Requirement
from .results import PolicyHit, RawObservation

log = logging.getLogger("rls_sentinel.executor")

_CMDS = {"SELECT": ["r"], "INSERT": ["a"], "UPDATE": ["w", "r"], "DELETE": ["d", "r"], "UPSERT": ["a", "w", "r"], "EXECUTE": []}

_FACTS_SQL = """
SELECT session_user::text, current_user::text, r.rolsuper, r.rolbypassrls, current_setting('row_security'),
       c.relrowsecurity, c.relforcerowsecurity, pg_has_role(current_user, c.relowner, 'USAGE'),
       c.relkind::text
FROM pg_roles r LEFT JOIN pg_class c ON c.oid = to_regclass(%s)
WHERE r.rolname = current_user
"""

_VIEW_FACTS_SQL = """
SELECT v.relkind::text,
       coalesce(v.reloptions::text[] && ARRAY['security_invoker=true', 'security_invoker=on'], false),
       pg_get_userbyid(v.relowner),
       (r.rolsuper OR r.rolbypassrls
        OR (b.relrowsecurity AND NOT b.relforcerowsecurity AND pg_has_role(v.relowner, b.relowner, 'USAGE')))
FROM pg_class v
JOIN pg_roles r ON r.oid = v.relowner
LEFT JOIN pg_class b ON b.oid = to_regclass(%s)
WHERE v.oid = to_regclass(%s)
"""

_FUNC_FACTS_SQL = """
SELECT p.prosecdef, pg_get_userbyid(p.proowner),
       (r.rolsuper OR r.rolbypassrls
        OR (b.relrowsecurity AND NOT b.relforcerowsecurity AND pg_has_role(p.proowner, b.relowner, 'USAGE')))
FROM pg_proc p
JOIN pg_roles r ON r.oid = p.proowner
LEFT JOIN pg_class b ON b.oid = to_regclass(%s)
WHERE p.pronamespace = %s::regnamespace AND p.proname = %s AND p.pronargs = %s
ORDER BY p.oid LIMIT 1
"""

_POLICIES_SQL = """
SELECT p.polname, p.polcmd::text, p.polpermissive
FROM pg_policy p
WHERE p.polrelid = to_regclass(%s)
  AND (p.polcmd = '*' OR p.polcmd = ANY(%s::text[]))
  AND (0 = ANY(p.polroles)
       OR EXISTS (SELECT 1 FROM unnest(p.polroles) AS r WHERE pg_has_role(current_user, r, 'USAGE')))
ORDER BY p.polname
"""

_CMD_NAME = {"r": "SELECT", "a": "INSERT", "w": "UPDATE", "d": "DELETE", "*": "ALL"}


def _regclass_text(conn: psycopg.Connection, schema: str, table: str) -> str:
    return sql.Identifier(schema, table).as_string(conn)


def _priv_ok(cur: psycopg.Cursor, rel_text: str, req: Requirement) -> bool:
    row = cur.execute("SELECT has_table_privilege(current_user, to_regclass(%s), %s)", (rel_text, req.privilege)).fetchone()
    if row and row[0]:
        return True
    cols = list(dict.fromkeys(req.columns))
    if not cols or req.privilege in ("DELETE",):
        return False
    row = cur.execute(
        "SELECT coalesce(bool_and(has_column_privilege(current_user, to_regclass(%s), c, %s)), false) "
        "FROM unnest(%s::text[]) AS c", (rel_text, req.privilege, cols)).fetchone()
    return bool(row and row[0])


class WorkerConnections:
    """One harness connection per worker thread."""

    def __init__(self, dsn: str, statement_timeout_ms: int):
        self._dsn = dsn
        self._timeout = statement_timeout_ms
        self._local = threading.local()
        self._all: list[psycopg.Connection] = []
        self._lock = threading.Lock()

    def _open(self) -> psycopg.Connection:
        conn = psycopg.connect(
            self._dsn, autocommit=False, connect_timeout=8,
            options=f"-c statement_timeout={int(self._timeout)} -c lock_timeout=1000 "
                    "-c idle_in_transaction_session_timeout=30000 -c application_name=rls-sentinel-harness",
        )
        with self._lock:
            self._all.append(conn)
        return conn

    def get(self) -> psycopg.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None or conn.closed:
            conn = self._open()
            self._local.conn = conn
        return conn

    def reset(self) -> psycopg.Connection:
        old = getattr(self._local, "conn", None)
        if old is not None:
            with contextlib.suppress(psycopg.Error):
                old.close()
        self._local.conn = None
        return self.get()

    def cancel_all(self) -> None:
        with self._lock:
            for c in self._all:
                try:
                    if not c.closed:
                        c.cancel()
                except psycopg.Error:
                    pass

    def close(self) -> None:
        with self._lock:
            for c in self._all:
                with contextlib.suppress(psycopg.Error):
                    c.close()
            self._all.clear()


def observe(
    conn: psycopg.Connection,
    plan: OpPlan,
    actor: Actor,
    *,
    guc_settings: list[tuple[str, str]] | None = None,
    row_json: dict[str, Any] | None = None,
) -> RawObservation:
    """Execute ``plan`` as ``actor`` inside a transaction that is always rolled back."""
    t0 = time.perf_counter()
    raw = RawObservation(sql_display=plan.display)
    try:
        with conn.transaction(force_rollback=True):
            cur = conn.cursor()
            try:
                cur.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(actor.pg_role)))
            except pgerr.InsufficientPrivilege as exc:
                raw.observed = "INFRA_ERROR"
                raw.sqlstate = exc.sqlstate
                raw.precondition_failed = f"The harness may not SET ROLE {actor.pg_role} (no genuine role membership)."
                return raw
            except pgerr.UndefinedObject:
                raw.observed = "INFRA_ERROR"
                raw.precondition_failed = f"Role '{actor.pg_role}' does not exist in the fixture."
                return raw

            base_text = _regclass_text(conn, plan.schema, plan.table) if plan.operation != "EXECUTE" else None
            access_text = _regclass_text(conn, plan.access_schema, plan.access_table) if plan.operation != "EXECUTE" else None
            facts = cur.execute(_FACTS_SQL, (base_text,)).fetchone()
            if facts is None:
                raw.observed = "INFRA_ERROR"
                raw.precondition_failed = "Could not read role facts."
                return raw
            (raw.session_user, raw.current_user, raw.role_superuser, raw.role_bypassrls, raw.row_security_setting,
             rls_enabled, rls_forced, owner_eff, relkind) = facts
            if plan.operation != "EXECUTE":
                if relkind is None:
                    raw.observed = "INFRA_ERROR"
                    raw.precondition_failed = f"Relation {plan.qualified_table} does not exist or is not visible."
                    return raw
                raw.rls_enabled, raw.rls_forced, raw.table_owner_effective = bool(rls_enabled), bool(rls_forced), bool(owner_eff)
                # RLS bypass logic per PostgreSQL: superuser / BYPASSRLS attribute (not inherited) / table owner unless FORCE.
                if raw.role_superuser:
                    raw.bypass_reason = "SUPERUSER"
                elif raw.role_bypassrls:
                    raw.bypass_reason = "BYPASSRLS"
                elif raw.table_owner_effective and not raw.rls_forced and raw.rls_enabled:
                    raw.bypass_reason = "TABLE_OWNER"
                raw.rls_applies = bool(raw.rls_enabled and raw.bypass_reason is None and raw.row_security_setting == "on")
                if plan.access_table != plan.table or plan.access_schema != plan.schema:
                    vf = cur.execute(_VIEW_FACTS_SQL, (base_text, access_text)).fetchone()
                    if vf and vf[0] in ("v", "m"):
                        invoker, view_owner, owner_bypass = bool(vf[1]), vf[2], bool(vf[3])
                        raw.sql_display += f"  -- via {'security_invoker' if invoker else 'owner-privileged'} view (owner {view_owner})"
                        if not invoker and raw.bypass_reason in (None, "TABLE_OWNER"):
                            # Base-table access is evaluated as the view owner, not as the actor.
                            raw.bypass_reason = "VIEW_OWNER_BYPASS" if owner_bypass else None
                            raw.rls_applies = bool(raw.rls_enabled and not owner_bypass)
                cmds = _CMDS[plan.operation]
                if cmds:
                    for name, cmd, perm in cur.execute(_POLICIES_SQL, (base_text, cmds)).fetchall():
                        raw.applicable_policies.append(PolicyHit(name=name, command=_CMD_NAME[cmd], permissive=bool(perm)))
                # SQL privilege gate, evaluated for the actor before running the statement
                raw.privilege_ok = all(_priv_ok(cur, access_text or "", r) for r in plan.requires) if plan.requires else True
            if plan.operation == "EXECUTE" and plan.data_table:
                _function_facts(cur, conn, plan, raw)
            if guc_settings:
                for k, v in guc_settings:
                    cur.execute("SELECT set_config(%s, %s, true)", (k, v))

            params = list(plan.params)
            if plan.needs_row_json:
                doc = dict(row_json or {})
                for k, v in plan.upsert_set.items():
                    if v is not None:
                        doc[k] = v
                params = [json.dumps(doc)]
            try:
                with conn.transaction():
                    cur.execute(plan.statement, params)
                    rows = cur.fetchall() if (plan.result_mode in ("rows", "function") and cur.description) else None
                    rowcount = cur.rowcount
            except pgerr.InsufficientPrivilege as exc:
                raw.sqlstate = "42501"
                raw.message = redact_text(exc.diag.message_primary or "")[:200]
                if raw.privilege_ok is False and plan.operation != "EXECUTE":
                    raw.observed, raw.gate = "GRANT_DENIED", "GRANT"
                elif "row-level security" in (exc.diag.message_primary or "") or (
                        exc.diag.table_name and plan.operation != "EXECUTE" and raw.privilege_ok):
                    raw.observed, raw.gate = "RLS_VIOLATION", "RLS"
                elif plan.operation == "EXECUTE" and "function" in (exc.diag.message_primary or ""):
                    raw.observed, raw.gate = "GRANT_DENIED", "GRANT"
                else:
                    raw.observed, raw.gate = "POLICY_DEPENDENCY_ERROR", "UNKNOWN"
                return raw
            except pgerr.QueryCanceled as exc:
                raw.observed, raw.sqlstate, raw.message = "TIMEOUT", exc.sqlstate, "statement timeout"
                return raw
            except pgerr.IntegrityError as exc:
                raw.observed, raw.sqlstate = "CONSTRAINT_ERROR", exc.sqlstate
                raw.message = redact_text(exc.diag.message_primary or "")[:200]
                return raw
            except pgerr.InvalidObjectDefinition as exc:  # 42P17 infinite recursion in policy
                raw.observed, raw.sqlstate = "POLICY_ERROR", exc.sqlstate
                raw.message = redact_text(exc.diag.message_primary or "")[:200]
                return raw
            except (pgerr.OperationalError, pgerr.InterfaceError):
                raise
            except psycopg.Error as exc:
                raw.observed, raw.sqlstate = "SQL_ERROR", getattr(exc, "sqlstate", None)
                raw.message = redact_text((exc.diag.message_primary or str(exc)) if hasattr(exc, "diag") else str(exc))[:200]
                if raw.sqlstate and raw.sqlstate.startswith("42P17"):
                    raw.observed = "POLICY_ERROR"
                return raw

            if plan.result_mode == "function":
                assert rows is not None
                count = len(rows) if len(rows) != 1 or (rows and len(rows[0]) != 1) else (0 if rows[0][0] is None else 1)
            elif plan.result_mode == "rows" and rows is not None:
                count = len(rows)
                raw.affected_pk_masked = [mask_identifier(r) for r in rows][:20]
            else:
                count = max(rowcount, 0) if plan.operation != "SELECT" else rowcount
            raw.row_count = count
            if plan.operation == "SELECT" or plan.operation == "EXECUTE":
                raw.observed = "ROW_RETURNED" if count > 0 else "NO_ROWS"
            elif plan.operation == "INSERT":
                raw.observed = "ROW_INSERTED" if count > 0 else "NO_ROWS"
            else:
                raw.observed = "ROWS_AFFECTED" if count > 0 else "NO_ROWS"
            if count > 0 and not raw.affected_pk_masked and plan.pk:
                raw.affected_pk_masked = [mask_identifier(tuple(plan.pk.values()))]
            if count > 0:
                raw.gate = "NONE"
            else:
                raw.gate = "RLS" if raw.rls_applies else "NONE"
    finally:
        raw.duration_ms = round((time.perf_counter() - t0) * 1000, 2)
    return raw


def _function_facts(cur: psycopg.Cursor, conn: psycopg.Connection, plan: OpPlan, raw: RawObservation) -> None:
    """Attribute RLS applicability for a function path: SECURITY INVOKER runs as the actor, DEFINER as the owner."""
    data_text = _regclass_text(conn, plan.data_schema, plan.data_table)
    facts = cur.execute(_FACTS_SQL, (data_text,)).fetchone()
    if not facts or facts[8] is None:
        return
    raw.rls_enabled, raw.rls_forced, raw.table_owner_effective = bool(facts[5]), bool(facts[6]), bool(facts[7])
    if raw.role_superuser:
        raw.bypass_reason = "SUPERUSER"
    elif raw.role_bypassrls:
        raw.bypass_reason = "BYPASSRLS"
    elif raw.table_owner_effective and not raw.rls_forced and raw.rls_enabled:
        raw.bypass_reason = "TABLE_OWNER"
    raw.rls_applies = bool(raw.rls_enabled and raw.bypass_reason is None and raw.row_security_setting == "on")
    nargs = len(plan.params)
    ff = cur.execute(_FUNC_FACTS_SQL, (data_text, plan.schema, plan.table, nargs)).fetchone()
    if ff:
        secdef, fowner, owner_bypass = bool(ff[0]), ff[1], bool(ff[2])
        raw.sql_display += f"  -- {'SECURITY DEFINER' if secdef else 'SECURITY INVOKER'} function (owner {fowner})"
        if secdef and raw.bypass_reason in (None, "TABLE_OWNER"):
            raw.bypass_reason = "FUNCTION_OWNER_BYPASS" if owner_bypass else None
            raw.rls_applies = bool(raw.rls_enabled and not owner_bypass)


def run_with_retry(workers: WorkerConnections, fn: Callable[[psycopg.Connection], RawObservation]) -> RawObservation:
    """Run ``fn``; on connection-level failures reconnect once, then report INFRA_ERROR (never DENY/PASS)."""
    last: Exception | None = None
    for attempt in range(2):
        try:
            conn = workers.get() if attempt == 0 else workers.reset()
            return fn(conn)
        except (pgerr.OperationalError, pgerr.InterfaceError) as exc:
            last = exc
            time.sleep(0.2)
    raw = RawObservation(observed="INFRA_ERROR", message=redact_text(str(last).splitlines()[0][:200]) if last else "connection failed")
    raw.precondition_failed = "Database connection error (not a denial)."
    return raw
