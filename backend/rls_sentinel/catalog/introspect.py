"""Catalog introspection: PostgreSQL catalog -> normalized :class:`Snapshot`."""

from __future__ import annotations

import hashlib
import json
import logging
from collections import defaultdict
from collections.abc import Callable
from typing import Any

import psycopg

from .. import RULESET_VERSION, __version__
from ..errors import UnsafeOperation
from ..redaction import redact_sql_expression
from .connection import CatalogSession
from .models import (
    ColumnRec,
    CoverageManifest,
    ExprDeps,
    ExtensionRec,
    ForeignKeyRec,
    FunctionRec,
    GrantRec,
    MembershipRec,
    PolicyRec,
    Provenance,
    RoleRec,
    SchemaRec,
    Snapshot,
    SourceInfo,
    TableRec,
    TriggerRec,
)

log = logging.getLogger("rls_sentinel.catalog")

MIN_SUPPORTED_MAJOR = 15
MAX_VERIFIED_MAJOR = 18

TENANT_COLUMN_HINTS = (
    "tenant_id", "org_id", "organization_id", "organisation_id", "account_id", "workspace_id",
    "company_id", "team_id", "customer_id", "project_id", "owner_id", "user_id",
)
_CMD: dict[str, Any] = {"r": "SELECT", "a": "INSERT", "w": "UPDATE", "d": "DELETE", "*": "ALL"}
_KIND: dict[str, Any] = {"r": "table", "p": "partitioned_table", "v": "view", "m": "materialized_view", "f": "foreign_table"}

DEFAULT_LIMITS = {
    "relations": 20000, "columns": 400000, "constraints": 100000, "triggers": 50000, "policies": 50000,
    "policy_deps": 200000, "roles": 10000, "memberships": 100000, "grants": 400000, "functions": 20000,
    "effective": 400000, "effective_roles": 200,
}


class Introspector:
    def __init__(
        self,
        session: CatalogSession,
        *,
        source: SourceInfo,
        schemas: list[str] | None = None,
        exclude_schemas: list[str] | None = None,
        store_expressions: bool = True,
        allow_privileged_inspector: bool = False,
        limits: dict[str, int] | None = None,
        on_progress: Callable[[str, dict[str, Any]], None] | None = None,
    ):
        self.s = session
        self.source = source
        self.include = schemas
        self.exclude = set(exclude_schemas or [])
        self.store_expressions = store_expressions
        self.allow_privileged = allow_privileged_inspector
        self.limits = {**DEFAULT_LIMITS, **(limits or {})}
        self.skipped: list[dict[str, Any]] = []
        self.notes: list[str] = []
        self._progress = on_progress or (lambda stage, info: None)

    # ---------------------------------------------------------------- helpers
    def _fetch(self, name: str, *, limit_key: str | None = None, required: bool = False, **params: Any) -> list[dict]:
        limit = self.limits.get(limit_key or name, 10000)
        try:
            with self.s.savepoint():
                rows = self.s.fetch(name, limit=limit + 1, **params)
        except psycopg.Error as exc:
            if required:
                raise
            self.skipped.append({"object_kind": name, "reason": type(exc).__name__,
                                 "sqlstate": getattr(exc, "sqlstate", None), "detail": str(exc).splitlines()[0][:160]})
            self._progress("skipped", {"query": name})
            return []
        if len(rows) > limit:
            self.skipped.append({"object_kind": name, "reason": "row_limit_reached", "limit": limit})
            self.notes.append(f"Catalog listing '{name}' stopped at its limit of {limit} rows; objects beyond it are not "
                              "analysed, so findings and graphs for them are missing.")
            rows = rows[:limit]
        self._progress("fetched", {"query": name, "rows": len(rows)})
        return rows

    def _expr(self, e: str | None) -> str | None:
        if e is None:
            return None
        return redact_sql_expression(e) if self.store_expressions else "«not retained»"

    # ------------------------------------------------------------------- main
    def run(self) -> Snapshot:
        server = self.s.fetch("server")[0]
        major = server["version_num"] // 10000
        if server["is_superuser"] and not self.allow_privileged:
            raise UnsafeOperation(
                "The inspection account is a superuser. Use a least-privilege read-only role "
                "(see docs/authorized-testing.md) or pass allow_privileged_inspector explicitly.",
            )
        if major < MIN_SUPPORTED_MAJOR:
            self.notes.append(f"PostgreSQL {major} is older than the supported range (15-18); results may be incomplete.")
        elif major > MAX_VERIFIED_MAJOR:
            self.notes.append(f"PostgreSQL {major} is newer than the versions this release was verified on (15-18).")
        if server["is_superuser"] or server["bypass_rls"]:
            self.notes.append("Inspector account is privileged (superuser/BYPASSRLS); this violates least-privilege guidance.")

        databases = [r["datname"] for r in self._fetch("databases")]
        schema_rows = self._fetch("schemas", limit_key="relations", required=True)
        schemas = [r["name"] for r in schema_rows]
        if self.include:
            schemas = [s for s in schemas if s in set(self.include)]
        schemas = [s for s in schemas if s not in self.exclude]
        sp = {"schemas": schemas}
        self._progress("schemas", {"count": len(schemas)})

        schema_recs = [
            SchemaRec(name=r["name"], owner=r["owner"], acl_default=r["acl_default"],
                      provenance=Provenance(ref=f"pg_namespace:{r['oid']}"))
            for r in schema_rows if r["name"] in schemas
        ]
        tables = self._tables(sp)
        policies = self._policies(sp)
        roles = self._roles()
        memberships = self._memberships(major)
        grants = self._grants(sp)
        functions = self._functions(sp)
        grants += self._function_grants(sp)
        extensions = [ExtensionRec(name=r["name"], version=r["version"]) for r in self._fetch("extensions")]

        eff, eff_fn, eff_cols, usage = self._effective(sp)
        self._check_policy_view_count(sp, len(policies))

        cov = CoverageManifest(
            postgres_version=server["version"],
            scan_mode="catalog_read_only",
            schemas_seen=len(schema_recs),
            tables_seen=len(tables),
            policies_seen=len(policies),
            roles_seen=len(roles),
            functions_seen=len(functions),
            source_row_data_collected=False,
            catalog_objects_skipped=self.skipped,
            runtime_tests_executed=False,
            coverage_notes=[
                "No behavioral assertion can be confirmed in static mode.",
                "Row data was not read; row counts are planner estimates from pg_class.reltuples.",
                *self.notes,
            ],
            inspector_role=server["current_user"],
            inspector_privileged=bool(server["is_superuser"] or server["bypass_rls"]),
        )
        snap = Snapshot(
            tool_version=__version__,
            ruleset_version=RULESET_VERSION,
            source=self.source,
            postgres_version=server["version"],
            postgres_version_num=server["version_num"],
            database=server["database"],
            databases_visible=databases,
            schemas=schema_recs,
            tables=tables,
            policies=policies,
            roles=roles,
            memberships=memberships,
            grants=grants,
            functions=functions,
            extensions=extensions,
            effective_table_privileges=eff,
            effective_function_execute=eff_fn,
            effective_column_select=eff_cols,
            schema_usage=usage,
            coverage=cov,
        )
        snap.schema_hash = compute_schema_hash(snap)
        return snap

    # ------------------------------------------------------------- sections
    def _tables(self, sp: dict) -> list[TableRec]:
        rels = self._fetch("relations", **sp)
        cols = self._fetch("columns", **sp)
        cons = self._fetch("constraints", **sp)
        trigs = self._fetch("triggers", **sp)
        vdeps = self._fetch("view_deps", limit_key="constraints", **sp)

        cols_by: dict[str, list[ColumnRec]] = defaultdict(list)
        for c in cols:
            q = f"{c['schema']}.{c['rel']}"
            cols_by[q].append(ColumnRec(
                name=c["name"], position=c["position"], type=c["type"], not_null=c["not_null"],
                has_default=c["has_default"], generated=c["generated"], identity=c["identity"],
                tenant_candidate=c["name"].lower() in TENANT_COLUMN_HINTS,
            ))
        pk: dict[str, list[str]] = {}
        uq: dict[str, list[list[str]]] = defaultdict(list)
        fks: dict[str, list[ForeignKeyRec]] = defaultdict(list)
        for k in cons:
            q = f"{k['schema']}.{k['rel']}"
            if k["type"] == "p":
                pk[q] = list(k["columns"])
            elif k["type"] == "u":
                uq[q].append(list(k["columns"]))
            elif k["type"] == "f":
                fks[q].append(ForeignKeyRec(name=k["name"], columns=list(k["columns"]),
                                            ref_table=k["ref_table"] or "", ref_columns=list(k["ref_columns"])))
        tg: dict[str, list[TriggerRec]] = defaultdict(list)
        for t in trigs:
            tg[f"{t['schema']}.{t['rel']}"].append(
                TriggerRec(name=t["name"], enabled=t["enabled"], function=t["function"], definition=t["definition"]))
        deps: dict[str, set[str]] = defaultdict(set)
        for d in vdeps:
            deps[f"{d['view_schema']}.{d['view_name']}"].add(f"{d['ref_schema']}.{d['ref_name']}")

        out: list[TableRec] = []
        for r in rels:
            q = f"{r['schema']}.{r['name']}"
            opts: dict[str, str | bool] = {}
            for o in r["reloptions"] or []:
                k, _, v = o.partition("=")
                opts[k] = v
            vdef = r["view_definition"]
            out.append(TableRec(
                schema=r["schema"], name=r["name"], kind=_KIND[r["relkind"]], owner=r["owner"],
                rls_enabled=r["rls_enabled"], rls_forced=r["rls_forced"],
                row_estimate=None if r["row_estimate"] is None or r["row_estimate"] < 0 else int(r["row_estimate"]),
                is_partition=r["is_partition"], parent=r["parent"], acl_default=r["acl_default"],
                extension_owned=r["extension_owned"], columns=cols_by.get(q, []),
                primary_key=pk.get(q, []), unique_constraints=uq.get(q, []), foreign_keys=fks.get(q, []),
                triggers=tg.get(q, []), options=opts,
                view_definition=self._expr(vdef) if vdef else None,
                view_depends_on=sorted(deps.get(q, set())),
                provenance=Provenance(ref=f"pg_class:{r['oid']}"),
            ))
        return out

    def _policies(self, sp: dict) -> list[PolicyRec]:
        rows = self._fetch("policies", **sp)
        dep_rows = self._fetch("policy_deps", **sp)
        by: dict[int, ExprDeps] = defaultdict(ExprDeps)
        for d in dep_rows:
            e = by[d["policy_oid"]]
            if d["kind"] == "column":
                e.columns.append(f"{d['schema']}.{d['name']}.{d['detail']}")
            elif d["kind"] == "relation":
                e.relations.append(f"{d['schema']}.{d['name']}")
            else:
                e.functions.append(f"{d['schema']}.{d['name']}({d['detail']})")
        out = []
        for r in rows:
            own = f"{r['schema']}.{r['rel']}"
            deps = by.get(r["oid"], ExprDeps())
            # pg_depend records column-level dependencies for referenced relations; derive the relation set from them
            rels = {c.rsplit(".", 1)[0] for c in deps.columns} | set(deps.relations)
            deps.relations = sorted(rels - {own})
            out.append(PolicyRec(
                name=r["name"], table=f"{r['schema']}.{r['rel']}", command=_CMD[r["cmd"]],
                roles=sorted(r["roles"]), permissive=r["permissive"],
                using_expr=self._expr(r["using_expr"]), check_expr=self._expr(r["check_expr"]),
                deps=deps, provenance=Provenance(ref=f"pg_policy:{r['oid']}"),
            ))
        return out

    def _roles(self) -> list[RoleRec]:
        return [
            RoleRec(name=r["name"], superuser=r["superuser"], inherit=r["inherit"], createrole=r["createrole"],
                    createdb=r["createdb"], login=r["login"], replication=r["replication"],
                    bypassrls=r["bypassrls"], connlimit=r["connlimit"], system=r["name"].startswith("pg_"),
                    provenance=Provenance(ref=f"pg_authid:{r['oid']}"))
            for r in self._fetch("roles")
        ]

    def _memberships(self, major: int) -> list[MembershipRec]:
        name = "memberships_pg16" if major >= 16 else "memberships_pg15"
        return [
            MembershipRec(role=r["role"], member=r["member"], grantor=r["grantor"], admin_option=r["admin_option"],
                          inherit_option=r["inherit_option"], set_option=r["set_option"],
                          provenance=Provenance(ref="pg_auth_members"))
            for r in self._fetch(name, limit_key="memberships")
        ]

    def _grants(self, sp: dict) -> list[GrantRec]:
        out: list[GrantRec] = []
        for r in self._fetch("relation_grants", limit_key="grants", **sp):
            out.append(GrantRec(object_type="table", object=f"{r['schema']}.{r['name']}", grantee=r["grantee"],
                                privilege=r["privilege"], grantable=r["grantable"], grantor=r["grantor"],
                                provenance=Provenance(ref=f"pg_class:{r['oid']}")))
        for r in self._fetch("column_grants", limit_key="grants", **sp):
            out.append(GrantRec(object_type="column", object=f"{r['schema']}.{r['name']}.{r['column']}",
                                grantee=r["grantee"], privilege=r["privilege"], grantable=r["grantable"],
                                grantor=r["grantor"], provenance=Provenance(ref=f"pg_attribute:{r['oid']}")))
        for r in self._fetch("schema_grants", limit_key="grants", **sp):
            out.append(GrantRec(object_type="schema", object=r["name"], grantee=r["grantee"], privilege=r["privilege"],
                                grantable=r["grantable"], grantor=r["grantor"],
                                provenance=Provenance(ref=f"pg_namespace:{r['oid']}")))
        for r in self._fetch("default_acls", limit_key="grants"):
            out.append(GrantRec(object_type="default", object=f"{r['for_role']}:{r['schema']}:{r['objtype']}",
                                grantee=r["grantee"], privilege=r["privilege"], grantable=r["grantable"],
                                provenance=Provenance(ref="pg_default_acl")))
        return out

    def _functions(self, sp: dict) -> list[FunctionRec]:
        return [
            FunctionRec(schema=r["schema"], name=r["name"], identity_args=r["identity_args"], owner=r["owner"],
                        security_definer=r["security_definer"], config=list(r["config"] or []),
                        language=r["language"], kind=r["kind"], leakproof=r["leakproof"],
                        volatility=r["volatility"], returns=r["returns"], acl_default=r["acl_default"],
                        public_execute=r["public_execute"], extension_owned=r["extension_owned"],
                        src_sha256=r["src_sha256"], provenance=Provenance(ref=f"pg_proc:{r['oid']}"))
            for r in self._fetch("functions", **sp)
        ]

    def _function_grants(self, sp: dict) -> list[GrantRec]:
        return [
            GrantRec(object_type="function", object=f"{r['schema']}.{r['name']}({r['identity_args']})",
                     grantee=r["grantee"], privilege=r["privilege"], grantable=r["grantable"], grantor=r["grantor"],
                     provenance=Provenance(ref=f"pg_proc:{r['oid']}"))
            for r in self._fetch("function_grants", limit_key="grants", **sp)
        ]

    def _effective(self, sp: dict):
        rl = self.limits["effective_roles"]
        p = {**sp, "role_limit": rl}
        eff: dict[str, dict[str, list[str]]] = defaultdict(dict)
        for r in self._fetch("effective_table_privileges", limit_key="effective", **p):
            eff[r["role"]][r["rel"]] = sorted(r["privs"])
        fn: dict[str, list[str]] = defaultdict(list)
        for r in self._fetch("effective_function_execute", limit_key="effective", **p):
            fn[r["role"]].append(r["fn"])
        cols: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
        for r in self._fetch("effective_column_select", limit_key="effective", **p):
            cols[r["role"]][r["rel"]].append(r["column"])
        usage: dict[str, list[str]] = defaultdict(list)
        for r in self._fetch("effective_schema_usage", limit_key="effective", **p):
            usage[r["role"]].append(r["schema"])
        return (
            {k: dict(v) for k, v in eff.items()},
            dict(fn),
            {k: {t: sorted(c) for t, c in v.items()} for k, v in cols.items()},
            dict(usage),
        )

    def _check_policy_view_count(self, sp: dict, n_policies: int) -> None:
        rows = self._fetch("policies_view_count", **{**sp})
        if rows and rows[0]["n"] != n_policies:
            self.notes.append(
                f"pg_policy returned {n_policies} policies but pg_policies reports {rows[0]['n']} (visibility difference).")


# --------------------------------------------------------------------------- hashing
def _canonical(snap: Snapshot) -> dict[str, Any]:
    """Normalized, order-independent, volatility-free projection used for the schema hash."""

    def dump(models: list[Any], *, exclude: set[str]) -> list[dict]:
        rows = [m.model_dump(mode="json", exclude={"provenance", *exclude}) for m in models]
        return sorted(rows, key=lambda d: json.dumps(d, sort_keys=True))

    return {
        "schemas": dump(snap.schemas, exclude={"acl_default"}),
        "tables": dump(snap.tables, exclude={"row_estimate"}),
        "policies": dump(snap.policies, exclude=set()),
        "roles": dump(snap.roles, exclude=set()),
        "memberships": dump(snap.memberships, exclude=set()),
        "grants": dump(snap.grants, exclude=set()),
        "functions": dump(snap.functions, exclude=set()),
        "eff": snap.effective_table_privileges,
    }


def compute_schema_hash(snap: Snapshot) -> str:
    blob = json.dumps(_canonical(snap), sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()
