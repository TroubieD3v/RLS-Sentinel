"""Normalized catalog model. Every record carries provenance; nothing here contains row data."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

EvidenceType = Literal["CATALOG_FACT", "STATIC_INFERENCE", "RUNTIME_OBSERVATION", "USER_EXPECTATION"]
PolicyCommand = Literal["ALL", "SELECT", "INSERT", "UPDATE", "DELETE"]
RelKind = Literal["table", "partitioned_table", "view", "materialized_view", "foreign_table"]

TABLE_PRIVS = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]


class Provenance(BaseModel):
    model_config = ConfigDict(frozen=False)

    source: Literal["catalog", "migration", "runtime", "user"] = "catalog"
    ref: str | None = None  # e.g. "pg_policy:16421"
    path: str | None = None  # migration file (relative)
    line: int | None = None


class SchemaRec(BaseModel):
    name: str
    owner: str
    acl_default: bool = True
    provenance: Provenance = Field(default_factory=Provenance)


class RoleRec(BaseModel):
    name: str
    superuser: bool
    inherit: bool
    createrole: bool
    createdb: bool
    login: bool
    replication: bool
    bypassrls: bool
    connlimit: int
    system: bool = False  # pg_* predefined role
    provenance: Provenance = Field(default_factory=Provenance)

    @property
    def bypasses_rls(self) -> bool:
        return self.superuser or self.bypassrls


class MembershipRec(BaseModel):
    role: str  # the granted role (group)
    member: str
    grantor: str | None = None
    admin_option: bool = False
    inherit_option: bool | None = None  # PG16+: per-grant; None => PG15, use member.rolinherit
    set_option: bool | None = None  # PG16+: per-grant; None => PG15 (always allowed)
    provenance: Provenance = Field(default_factory=Provenance)


class GrantRec(BaseModel):
    object_type: Literal["table", "column", "schema", "function", "default"]
    object: str  # qualified name; for columns "schema.table.column"
    grantee: str  # role name or "PUBLIC"
    privilege: str
    grantable: bool = False
    grantor: str | None = None
    provenance: Provenance = Field(default_factory=Provenance)


class ColumnRec(BaseModel):
    name: str
    position: int
    type: str
    not_null: bool = False
    has_default: bool = False
    generated: bool = False
    identity: bool = False
    tenant_candidate: bool = False


class ForeignKeyRec(BaseModel):
    name: str
    columns: list[str]
    ref_table: str
    ref_columns: list[str]


class TriggerRec(BaseModel):
    name: str
    enabled: str
    function: str | None = None
    definition: str | None = None


class TableRec(BaseModel):
    schema_name: str = Field(alias="schema")
    name: str
    kind: RelKind
    owner: str
    rls_enabled: bool = False
    rls_forced: bool = False
    row_estimate: int | None = None
    is_partition: bool = False
    parent: str | None = None
    acl_default: bool = True
    extension_owned: bool = False
    columns: list[ColumnRec] = Field(default_factory=list)
    primary_key: list[str] = Field(default_factory=list)
    unique_constraints: list[list[str]] = Field(default_factory=list)
    foreign_keys: list[ForeignKeyRec] = Field(default_factory=list)
    triggers: list[TriggerRec] = Field(default_factory=list)
    options: dict[str, str | bool] = Field(default_factory=dict)  # security_invoker, security_barrier, check_option
    view_definition: str | None = None
    view_depends_on: list[str] = Field(default_factory=list)
    provenance: Provenance = Field(default_factory=Provenance)

    model_config = ConfigDict(populate_by_name=True)

    @property
    def qualified(self) -> str:
        return f"{self.schema_name}.{self.name}"

    @property
    def is_view(self) -> bool:
        return self.kind in ("view", "materialized_view")

    @property
    def security_invoker(self) -> bool:
        return str(self.options.get("security_invoker", "")).lower() in ("true", "on", "1")

    @property
    def security_barrier(self) -> bool:
        return str(self.options.get("security_barrier", "")).lower() in ("true", "on", "1")


class ExprDeps(BaseModel):
    columns: list[str] = Field(default_factory=list)  # "schema.table.column"
    functions: list[str] = Field(default_factory=list)  # "schema.name(args)" (user-defined only; pg_catalog is pinned)
    relations: list[str] = Field(default_factory=list)


class PolicyRec(BaseModel):
    name: str
    table: str  # qualified
    command: PolicyCommand
    roles: list[str]  # ["PUBLIC"] or role names
    permissive: bool
    using_expr: str | None = None
    check_expr: str | None = None
    deps: ExprDeps = Field(default_factory=ExprDeps)
    provenance: Provenance = Field(default_factory=Provenance)

    @property
    def id(self) -> str:
        return f"policy:{self.table}:{self.name}"


class FunctionRec(BaseModel):
    schema_name: str = Field(alias="schema")
    name: str
    identity_args: str
    owner: str
    security_definer: bool
    config: list[str] = Field(default_factory=list)
    language: str
    kind: str  # f p a w
    leakproof: bool = False
    volatility: str = "v"
    returns: str | None = None
    acl_default: bool = True
    public_execute: bool = False
    extension_owned: bool = False
    src_sha256: str | None = None
    provenance: Provenance = Field(default_factory=Provenance)

    model_config = ConfigDict(populate_by_name=True)

    @property
    def qualified(self) -> str:
        return f"{self.schema_name}.{self.name}({self.identity_args})"

    @property
    def has_fixed_search_path(self) -> bool:
        return any(c.lower().startswith("search_path=") for c in self.config)


class ExtensionRec(BaseModel):
    name: str
    version: str


class CoverageManifest(BaseModel):
    postgres_version: str
    scan_mode: str = "catalog_read_only"
    schemas_seen: int = 0
    tables_seen: int = 0
    policies_seen: int = 0
    roles_seen: int = 0
    functions_seen: int = 0
    source_row_data_collected: bool = False
    catalog_objects_skipped: list[dict] = Field(default_factory=list)
    runtime_tests_executed: bool = False
    coverage_notes: list[str] = Field(default_factory=list)
    inspector_role: str | None = None
    inspector_privileged: bool = False


class SourceInfo(BaseModel):
    kind: Literal["live_source", "fixture", "file"] = "live_source"
    alias: str = ""
    mode: Literal["READ-ONLY SOURCE", "DISPOSABLE LAB", "STATIC SQL"] = "READ-ONLY SOURCE"
    display_target: str | None = None  # host:port/db with no credentials


class Snapshot(BaseModel):
    format: str = "rls-sentinel-snapshot/1"
    tool_version: str
    ruleset_version: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: SourceInfo
    postgres_version: str
    postgres_version_num: int
    database: str
    databases_visible: list[str] = Field(default_factory=list)
    schemas: list[SchemaRec] = Field(default_factory=list)
    tables: list[TableRec] = Field(default_factory=list)
    policies: list[PolicyRec] = Field(default_factory=list)
    roles: list[RoleRec] = Field(default_factory=list)
    memberships: list[MembershipRec] = Field(default_factory=list)
    grants: list[GrantRec] = Field(default_factory=list)
    functions: list[FunctionRec] = Field(default_factory=list)
    extensions: list[ExtensionRec] = Field(default_factory=list)
    # role -> qualified relation -> privileges effective per has_table_privilege() (SQL gate only)
    effective_table_privileges: dict[str, dict[str, list[str]]] = Field(default_factory=dict)
    # role -> qualified function -> True if EXECUTE effective
    effective_function_execute: dict[str, list[str]] = Field(default_factory=dict)
    # role -> "schema.table" -> columns with effective SELECT through column-level ACL entries
    effective_column_select: dict[str, dict[str, list[str]]] = Field(default_factory=dict)
    schema_usage: dict[str, list[str]] = Field(default_factory=dict)  # role -> schemas with effective USAGE
    coverage: CoverageManifest
    schema_hash: str = ""

    model_config = ConfigDict(populate_by_name=True)

    # ---- convenience lookups (not serialized) ----
    # Indexes are rebuilt whenever the underlying list object or its length changes, so callers that replace or
    # append to snapshot lists still get correct answers; lookups are O(1) instead of a scan per call.
    _idx_tables: tuple[int, int, dict[str, TableRec]] | None = PrivateAttr(default=None)
    _idx_roles: tuple[int, int, dict[str, RoleRec]] | None = PrivateAttr(default=None)
    _idx_policies: tuple[int, int, dict[str, list[PolicyRec]]] | None = PrivateAttr(default=None)

    def table(self, qualified: str) -> TableRec | None:
        c = self._idx_tables
        if c is None or c[0] != id(self.tables) or c[1] != len(self.tables):
            c = self._idx_tables = (id(self.tables), len(self.tables), {t.qualified: t for t in reversed(self.tables)})
        return c[2].get(qualified)

    def role(self, name: str) -> RoleRec | None:
        c = self._idx_roles
        if c is None or c[0] != id(self.roles) or c[1] != len(self.roles):
            c = self._idx_roles = (id(self.roles), len(self.roles), {r.name: r for r in reversed(self.roles)})
        return c[2].get(name)

    def policies_for(self, qualified: str) -> list[PolicyRec]:
        c = self._idx_policies
        if c is None or c[0] != id(self.policies) or c[1] != len(self.policies):
            by: dict[str, list[PolicyRec]] = {}
            for p in self.policies:
                by.setdefault(p.table, []).append(p)
            c = self._idx_policies = (id(self.policies), len(self.policies), by)
        return list(c[2].get(qualified, []))
