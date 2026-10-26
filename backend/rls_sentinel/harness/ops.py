"""Constrained operation DSL -> parameterized SQL.

Every statement is generated from structured fields. Identifiers are composed with
``psycopg.sql.Identifier``; values are always bound parameters. No SQL text from the spec is ever
executed.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from psycopg import sql

from ..errors import SpecError
from ..expectations.models import Actor, Expectation, Resource, Spec
from ..identifiers import parse_qualified
from ..redaction import mask_identifier, redact_text

_NS = uuid.UUID("5e11e11e-0000-4000-8000-00000000d51d")


@dataclass
class Requirement:
    privilege: str  # SELECT | INSERT | UPDATE | DELETE
    columns: list[str] = field(default_factory=list)  # empty => table-level only


@dataclass
class OpPlan:
    case_id: str
    operation: str
    schema: str  # base table schema (for catalog probes)
    table: str
    access_schema: str  # relation actually addressed (view or table)
    access_table: str
    statement: sql.Composable
    params: list[Any]
    display: str
    requires: list[Requirement]
    result_mode: str  # "rows" | "rowcount" | "function"
    pk: dict[str, Any] = field(default_factory=dict)
    claims: dict[str, str] | None = None
    needs_row_json: bool = False  # UPSERT: proposed row copied from the fixture admin's view of the target
    upsert_set: dict[str, Any] = field(default_factory=dict)
    upsert_conflict_cols: list[str] = field(default_factory=list)
    upsert_update_cols: list[str] = field(default_factory=list)
    resource_id: str | None = None
    data_schema: str = ""  # EXECUTE: schema/table of the protected resource the function is expected to guard
    data_table: str = ""

    @property
    def qualified_table(self) -> str:
        return f"{self.schema}.{self.table}"


def _val(token: Any, *, spec: Spec, actor: Actor, case_id: str) -> Any:
    if not isinstance(token, str) or not token.startswith("$"):
        return token
    if token == "$uuid":  # noqa: S105 - DSL placeholder, not a credential
        return str(uuid.uuid5(_NS, case_id))
    if token == "$actor_tenant":  # noqa: S105
        if actor.tenant is None:
            raise SpecError(f"Token $actor_tenant used but actor '{actor.id}' has no tenant.")
        return spec.tenant_value(actor.tenant)
    if token.startswith("$tenant:"):
        return spec.tenant_value(token.split(":", 1)[1])
    if token.startswith("$pk:"):
        rid, _, c = token.split(":", 1)[1].partition(".")
        r = spec.resource(rid)
        if r is None or c not in r.pk:
            raise SpecError(f"Unknown pk token {token}")
        return r.pk[c]
    raise SpecError(f"Unknown token {token}")


def _display_val(v: Any) -> str:
    s = redact_text(str(v))
    return s if len(s) <= 48 else s[:45] + "…"


def _where(pk: dict[str, Any]) -> tuple[sql.Composable, list[Any]]:
    conds = [sql.SQL("{} = %s").format(sql.Identifier(c)) for c in pk]
    return sql.SQL(" AND ").join(conds), list(pk.values())


def _pk_display(pk: dict[str, Any]) -> str:
    return " AND ".join(f'"{c}" = ${i + 1}' for i, c in enumerate(pk))


def build_plan(spec: Spec, exp: Expectation, *, claims: dict[str, str] | None) -> OpPlan:
    actor = spec.actor(exp.actor)
    if actor is None:
        raise SpecError(f"Unknown actor '{exp.actor}'")
    res: Resource | None = spec.resource(exp.resource) if exp.resource else None
    qualified = exp.table or (res.table if res else None)
    schema = table = ""
    if qualified:
        schema, table = parse_qualified(qualified)
    a_schema, a_table = (parse_qualified(exp.via) if exp.via else (schema, table))
    rel = sql.Identifier(a_schema, a_table)
    tcfg = spec.table_config(qualified) if qualified else None
    cid = exp.id
    op = exp.operation

    if op == "SELECT":
        assert res is not None
        cols = exp.columns
        cols_sql = sql.SQL(", ").join(sql.Identifier(c) for c in cols) if cols else sql.SQL("1")
        where, params = _where(res.pk)
        stmt = sql.SQL("SELECT {} FROM {} WHERE {}").format(cols_sql, rel, where)
        disp = f'SELECT {", ".join(f"""\"{c}\"""" for c in cols) if cols else "1"} FROM "{a_schema}"."{a_table}" WHERE {_pk_display(res.pk)}'
        disp += "  -- " + ", ".join(f"${i + 1} = {mask_identifier(v)}" for i, v in enumerate(params))
        return OpPlan(cid, op, schema, table, a_schema, a_table, stmt, params, disp,
                      [Requirement("SELECT", [*cols, *res.pk])], "rows", pk=dict(res.pk), claims=claims, resource_id=res.id)

    if op == "INSERT":
        row: dict[str, Any] = {k: _val(v, spec=spec, actor=actor, case_id=cid) for k, v in exp.row.items()}
        if exp.as_tenant:
            assert tcfg and tcfg.tenant_column
            row[tcfg.tenant_column] = spec.tenant_value(exp.as_tenant)
        cols = list(row)
        placeholders = sql.SQL(", ").join(sql.SQL("%s") for _ in cols)
        stmt = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(rel, sql.SQL(", ").join(sql.Identifier(c) for c in cols), placeholders)
        pkcols: list[str] = []
        if exp.returning:
            pkcols = list(res.pk) if res else list(row)[:1]
            stmt = sql.SQL("{} RETURNING {}").format(stmt, sql.SQL(", ").join(sql.Identifier(c) for c in pkcols))
        disp = f'INSERT INTO "{a_schema}"."{a_table}" ({", ".join(f"""\"{c}\"""" for c in cols)}) VALUES ({", ".join(f"${i + 1}" for i in range(len(cols)))})'
        if exp.returning:
            disp += " RETURNING " + ", ".join(f'"{c}"' for c in pkcols)
        disp += "  -- " + ", ".join(f"${i + 1} = {_display_val(v)}" for i, v in enumerate(row.values()))
        reqs = [Requirement("INSERT", cols)]
        if exp.returning:
            reqs.append(Requirement("SELECT", pkcols))
        return OpPlan(cid, op, schema, table, a_schema, a_table, stmt, list(row.values()), disp, reqs,
                      "rows" if exp.returning else "rowcount", claims=claims, resource_id=res.id if res else None)

    if op in ("UPDATE", "UPSERT"):
        assert res is not None
        assigns: dict[str, Any] = {k: _val(v, spec=spec, actor=actor, case_id=cid) for k, v in exp.set.items()}
        if exp.set_tenant:
            assert tcfg and tcfg.tenant_column
            assigns[tcfg.tenant_column] = spec.tenant_value(exp.set_tenant)
        if not assigns:
            assert tcfg and tcfg.touch_column
            assigns = {tcfg.touch_column: None}  # sentinel: SET col = col
        noop = [k for k, v in assigns.items() if v is None and tcfg and k == tcfg.touch_column and not exp.set and not exp.set_tenant]
        if op == "UPDATE":
            set_parts, params = [], []
            for k, v in assigns.items():
                if k in noop:
                    set_parts.append(sql.SQL("{0} = {0}").format(sql.Identifier(k)))
                else:
                    set_parts.append(sql.SQL("{} = %s").format(sql.Identifier(k)))
                    params.append(v)
            where, wparams = _where(res.pk)
            stmt = sql.SQL("UPDATE {} SET {} WHERE {}").format(rel, sql.SQL(", ").join(set_parts), where)
            params += wparams
            reqs = [Requirement("UPDATE", list(assigns)), Requirement("SELECT", list(res.pk))]
            if exp.returning:
                stmt = sql.SQL("{} RETURNING {}").format(stmt, sql.SQL(", ").join(sql.Identifier(c) for c in res.pk))
            changed = [x for x in assigns if x not in noop]
            n = len(changed)
            disp = f'UPDATE "{a_schema}"."{a_table}" SET ' + ", ".join(
                f'"{k}" = "{k}"' if k in noop else f'"{k}" = ${changed.index(k) + 1}' for k in assigns)
            disp += " WHERE " + " AND ".join(f'"{c}" = ${n + i + 1}' for i, c in enumerate(res.pk))
            if exp.returning:
                disp += " RETURNING " + ", ".join(f'"{c}"' for c in res.pk)
            disp += "  -- " + ", ".join(
                [f"${i + 1} = {_display_val(v)}" for i, v in enumerate(v for k, v in assigns.items() if k not in noop)]
                + [f"${n + i + 1} = {mask_identifier(v)}" for i, v in enumerate(wparams)])
            return OpPlan(cid, op, schema, table, a_schema, a_table, stmt, params, disp, reqs,
                          "rows" if exp.returning else "rowcount", pk=dict(res.pk), claims=claims, resource_id=res.id)
        # UPSERT: INSERT ... ON CONFLICT (pk) DO UPDATE using the target row as the proposed row
        base = sql.Identifier(schema, table)
        update_cols = list(assigns)
        set_sql = sql.SQL(", ").join(sql.SQL("{0} = EXCLUDED.{0}").format(sql.Identifier(k)) for k in update_cols)
        stmt = sql.SQL(
            "INSERT INTO {rel} SELECT * FROM jsonb_populate_record(NULL::{base}, %s::jsonb) "
            "ON CONFLICT ({conflict}) DO UPDATE SET {set}"
        ).format(rel=rel, base=base, conflict=sql.SQL(", ").join(sql.Identifier(c) for c in res.pk), set=set_sql)
        if exp.returning:
            stmt = sql.SQL("{} RETURNING {}").format(stmt, sql.SQL(", ").join(sql.Identifier(c) for c in res.pk))
        disp = (f'INSERT INTO "{a_schema}"."{a_table}" SELECT * FROM jsonb_populate_record(NULL::"{schema}"."{table}", $1) '
                f'ON CONFLICT ({", ".join(f"""\"{c}\"""" for c in res.pk)}) DO UPDATE SET '
                + ", ".join(f'"{k}" = EXCLUDED."{k}"' for k in update_cols)
                + "  -- $1 = proposed row (copy of target row with assignments applied; contents not retained)")
        plan = OpPlan(cid, op, schema, table, a_schema, a_table, stmt, [], disp,
                      [Requirement("INSERT", []), Requirement("UPDATE", update_cols), Requirement("SELECT", list(res.pk))],
                      "rows" if exp.returning else "rowcount", pk=dict(res.pk), claims=claims, needs_row_json=True,
                      upsert_set={k: (None if k in noop else v) for k, v in assigns.items()},
                      upsert_conflict_cols=list(res.pk), upsert_update_cols=update_cols, resource_id=res.id)
        return plan

    if op == "DELETE":
        assert res is not None
        where, params = _where(res.pk)
        stmt = sql.SQL("DELETE FROM {} WHERE {}").format(rel, where)
        reqs = [Requirement("DELETE", []), Requirement("SELECT", list(res.pk))]
        if exp.returning:
            stmt = sql.SQL("{} RETURNING {}").format(stmt, sql.SQL(", ").join(sql.Identifier(c) for c in res.pk))
        disp = f'DELETE FROM "{a_schema}"."{a_table}" WHERE {_pk_display(res.pk)}'
        if exp.returning:
            disp += " RETURNING " + ", ".join(f'"{c}"' for c in res.pk)
        disp += "  -- " + ", ".join(f"${i + 1} = {mask_identifier(v)}" for i, v in enumerate(params))
        return OpPlan(cid, op, schema, table, a_schema, a_table, stmt, params, disp, reqs,
                      "rows" if exp.returning else "rowcount", pk=dict(res.pk), claims=claims, resource_id=res.id)

    if op == "EXECUTE":
        assert exp.function
        fs, fn = parse_qualified(exp.function)
        args = [_val(a, spec=spec, actor=actor, case_id=cid) for a in exp.args]
        stmt = sql.SQL("SELECT * FROM {}({})").format(sql.Identifier(fs, fn), sql.SQL(", ").join(sql.SQL("%s") for _ in args))
        disp = f'SELECT * FROM "{fs}"."{fn}"({", ".join(f"${i + 1}" for i in range(len(args)))})'
        disp += "  -- " + ", ".join(f"${i + 1} = {mask_identifier(a) if _looks_like_id(a) else _display_val(a)}" for i, a in enumerate(args))
        return OpPlan(cid, op, fs, fn, fs, fn, stmt, args, disp, [], "function", claims=claims,
                      resource_id=res.id if res else None, data_schema=schema, data_table=table)
    raise SpecError(f"Unsupported operation {op}")


def _looks_like_id(v: Any) -> bool:
    return isinstance(v, str) and len(v) >= 16 and "-" in v


def baseline_exists_query(res: Resource) -> tuple[sql.Composable, list[Any]]:
    schema, table = parse_qualified(res.table)
    where, params = _where(res.pk)
    return sql.SQL("SELECT count(*) FROM {} WHERE {}").format(sql.Identifier(schema, table), where), params


def baseline_row_query(res: Resource) -> tuple[sql.Composable, list[Any]]:
    schema, table = parse_qualified(res.table)
    where, params = _where(res.pk)
    return sql.SQL("SELECT to_jsonb(t) FROM {} t WHERE {}").format(sql.Identifier(schema, table), where), params
