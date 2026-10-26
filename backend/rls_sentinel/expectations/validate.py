"""Catalog-aware validation: do the spec's roles, resources, columns and operations exist and fit?"""

from __future__ import annotations

from ..catalog.models import Snapshot, TableRec
from ..identifiers import parse_qualified
from .models import Spec


def validate_against_snapshot(spec: Spec, snap: Snapshot) -> list[dict]:
    issues: list[dict] = []

    def add(level: str, path: str, msg: str) -> None:
        issues.append({"level": level, "path": path, "message": msg})

    tables = {t.qualified: t for t in snap.tables}
    roles = {r.name: r for r in snap.roles}

    def get_table(q: str, path: str) -> TableRec | None:
        try:
            s, n = parse_qualified(q)
        except Exception as exc:
            add("error", path, str(exc))
            return None
        t = tables.get(f"{s}.{n}")
        if t is None:
            add("error", path, f"Relation {s}.{n} does not exist (or is not visible to the inspector).")
        return t

    for i, a in enumerate(spec.actors):
        r = roles.get(a.pg_role)
        if r is None:
            add("error", f"actors.{i}.pg_role", f"Role '{a.pg_role}' does not exist.")
            continue
        if r.superuser and not a.expect_bypass:
            add("warning", f"actors.{i}", f"Role '{a.pg_role}' is a superuser; its cases cannot test policies (set expect_bypass: true if intended).")
        elif r.bypassrls and not a.expect_bypass:
            add("warning", f"actors.{i}", f"Role '{a.pg_role}' has BYPASSRLS; its cases cannot test policies (set expect_bypass: true if intended).")

    for i, rsrc in enumerate(spec.resources):
        t = get_table(rsrc.table, f"resources.{i}.table")
        if not t:
            continue
        colnames = {c.name for c in t.columns}
        for k in rsrc.pk:
            if k not in colnames:
                add("error", f"resources.{i}.pk.{k}", f"Column '{k}' does not exist on {t.qualified}.")
        if t.primary_key and set(rsrc.pk) != set(t.primary_key) and not any(set(rsrc.pk) == set(u) for u in t.unique_constraints):
            add("warning", f"resources.{i}.pk", f"Declared key {sorted(rsrc.pk)} differs from the primary key {t.primary_key}; the lookup may match several rows.")

    for i, tc in enumerate(spec.tables):
        t = get_table(tc.table, f"tables.{i}.table")
        if not t:
            continue
        tcols = {c.name for c in t.columns}
        for fld, v in (("tenant_column", tc.tenant_column), ("touch_column", tc.touch_column)):
            if v and v not in tcols:
                add("error", f"tables.{i}.{fld}", f"Column '{v}' does not exist on {t.qualified}.")
        for j, sc in enumerate(tc.sensitive_columns):
            if sc.column not in tcols:
                add("error", f"tables.{i}.sensitive_columns.{j}", f"Column '{sc.column}' does not exist on {t.qualified}.")
        if t.kind in ("view", "materialized_view", "foreign_table"):
            add("warning", f"tables.{i}", f"{t.qualified} is a {t.kind}; RLS policies attach to base tables.")

    for i, p in enumerate(spec.privileges):
        get_table(p.table, f"privileges.{i}.table")
        if p.role not in roles and p.role != "PUBLIC":
            add("error", f"privileges.{i}.role", f"Role '{p.role}' does not exist.")

    for i, e in enumerate(spec.expectations):
        base = f"expectations.{i}"
        rs = spec.resource(e.resource) if e.resource else None
        q = e.table or (rs.table if rs else None)
        t = get_table(q, base) if q else None
        if e.via:
            vt = get_table(e.via, f"{base}.via")
            vcols = {c.name for c in vt.columns} if vt else set()
            if vt and rs and not set(rs.pk) <= vcols:
                add("error", f"{base}.via", f"View {e.via} does not expose the resource key columns {sorted(rs.pk)}.")
        if t is None:
            if e.operation == "EXECUTE" and e.function:
                s, n = parse_qualified(e.function)
                if not any(f.schema_name == s and f.name == n for f in snap.functions):
                    add("error", f"{base}.function", f"Function {s}.{n} does not exist.")
            continue
        cols = {c.name: c for c in t.columns}
        for c in e.columns:
            if c not in cols:
                add("error", f"{base}.columns", f"Column '{c}' does not exist on {t.qualified}.")
        for c in e.set:
            if c not in cols:
                add("error", f"{base}.set", f"Column '{c}' does not exist on {t.qualified}.")
            elif cols[c].generated:
                add("error", f"{base}.set", f"Column '{c}' is generated and cannot be assigned.")
        if e.operation == "INSERT":
            for c in e.row:
                if c not in cols:
                    add("error", f"{base}.row", f"Column '{c}' does not exist on {t.qualified}.")
            tcfg = spec.table_config(t.qualified)
            provided = set(e.row) | ({tcfg.tenant_column} if (e.as_tenant and tcfg and tcfg.tenant_column) else set())
            for name, col in cols.items():
                if col.not_null and not col.has_default and not col.identity and not col.generated and name not in provided:
                    add("error", f"{base}.row", f"NOT NULL column '{name}' has no default and is missing from 'row'; "
                                               "the insert would fail on a constraint before RLS can decide.")
        if e.operation in ("UPDATE", "UPSERT", "DELETE") and t.kind not in ("table", "partitioned_table") and not e.via:
            add("warning", base, f"{t.qualified} is a {t.kind}.")
    return issues
