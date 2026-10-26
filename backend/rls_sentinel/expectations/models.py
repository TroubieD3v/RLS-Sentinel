"""Declarative authorization specification (the *expected* policy), independent of database metadata."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Operation = Literal["SELECT", "INSERT", "UPDATE", "DELETE", "UPSERT", "EXECUTE"]
Expected = Literal["ALLOW", "DENY", "NO_ROWS", "ERROR_EXPECTED"]
DenyGate = Literal["rls", "grant", "any"]
IdentityMode = Literal["postgres_roles", "supabase_synthetic"]
ActorKind = Literal["user", "anonymous", "service", "admin", "support", "owner"]
Scalar = str | int | float | bool | None

_FORBIDDEN_RAW_KEYS = {"sql", "query", "statement", "raw", "raw_sql", "ddl", "dml", "script"}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @model_validator(mode="before")
    @classmethod
    def _no_raw_sql(cls, data: Any) -> Any:
        if isinstance(data, dict):
            bad = _FORBIDDEN_RAW_KEYS & {str(k).lower() for k in data}
            if bad:
                raise ValueError(
                    f"Raw SQL field(s) {sorted(bad)} are not accepted in specs. "
                    "Use the constrained operation DSL (operation/resource/set/row/columns/function)."
                )
        return data


IdStr = Annotated[str, Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9_.\-:]+$")]
RoleName = Annotated[str, Field(min_length=1, max_length=63)]


class SourceRef(_Strict):
    type: Literal["fixture", "catalog_snapshot", "live_source"] = "fixture"
    name: str = ""
    variant: Literal["vulnerable", "secure"] | None = None


class Actor(_Strict):
    id: IdStr
    pg_role: RoleName
    tenant: str | None = None
    kind: ActorKind = "user"
    description: str = ""
    claims: dict[str, str] = Field(default_factory=dict, description="Synthetic JWT-style claims (supabase_synthetic mode only).")
    expect_bypass: bool = Field(
        default=False,
        description="Set true only when the case deliberately tests a superuser/BYPASSRLS/owner role.",
    )


class Tenant(_Strict):
    id: IdStr
    value: Scalar = None
    name: str = ""


class Resource(_Strict):
    id: IdStr
    table: str
    pk: dict[str, Scalar] = Field(min_length=1)
    tenant: str | None = None
    description: str = ""


class SensitiveColumn(_Strict):
    column: str
    allowed_roles: list[RoleName] = Field(default_factory=list)


class TableConfig(_Strict):
    table: str
    tenant_column: str | None = None
    protected: bool = True
    touch_column: str | None = Field(default=None, description="Column used for harmless no-op UPDATE tests (SET col = col).")
    sensitive_columns: list[SensitiveColumn] = Field(default_factory=list)


class Expectation(_Strict):
    id: IdStr
    actor: str
    operation: Operation
    expected: Expected
    resource: str | None = None
    table: str | None = None
    description: str = ""
    via: str | None = Field(default=None, description="Access the resource through this view/relation instead of the base table.")
    columns: list[str] = Field(default_factory=list, description="SELECT: restrict to these columns (column-level checks).")
    set: dict[str, Scalar] = Field(default_factory=dict, description="UPDATE/UPSERT: column assignments.")
    set_tenant: str | None = Field(default=None, description="UPDATE/UPSERT: move the row to this tenant (exercises WITH CHECK).")
    as_tenant: str | None = Field(default=None, description="INSERT: shorthand for the tenant column value of the new row.")
    row: dict[str, Scalar] = Field(default_factory=dict, description="INSERT: column values; tokens $uuid, $tenant:<id>, $pk:<resource>.<col>.")
    returning: bool = False
    function: str | None = None
    args: list[Scalar] = Field(default_factory=list)
    deny_gate: DenyGate = Field(
        default="rls",
        description="Which gate must produce a DENY. 'rls' (default) requires the denial to come from row-level security; "
        "'grant' requires an SQL privilege error; 'any' accepts either.",
    )
    expect_sqlstate: str | None = Field(default=None, pattern=r"^[0-9A-Z]{5}$")
    claims_override: dict[str, str] | None = Field(
        default=None, description="Forged claims instead of the actor's own (tests unsafe identity-context trust)."
    )
    rule: str | None = Field(default=None, pattern=r"^RLS-\d{3}$", description="Optional rule hint for findings.")
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _shape(self) -> Expectation:
        op = self.operation
        if op in ("SELECT", "UPDATE", "DELETE", "UPSERT") and not self.resource:
            raise ValueError(f"{op} expectations require 'resource'.")
        if op == "INSERT" and not (self.table or self.resource):
            raise ValueError("INSERT expectations require 'table' (or a resource whose table is used).")
        if op == "INSERT" and not self.row:
            raise ValueError("INSERT expectations require 'row'.")
        if op == "EXECUTE" and not self.function:
            raise ValueError("EXECUTE expectations require 'function'.")
        if op != "EXECUTE" and (self.function or self.args):
            raise ValueError("'function'/'args' are only valid for EXECUTE.")
        if op != "SELECT" and self.columns:
            raise ValueError("'columns' is only valid for SELECT.")
        if op not in ("UPDATE", "UPSERT") and (self.set or self.set_tenant):
            raise ValueError("'set'/'set_tenant' are only valid for UPDATE/UPSERT.")
        if op != "INSERT" and (self.row or self.as_tenant):
            raise ValueError("'row'/'as_tenant' are only valid for INSERT.")
        if self.expected == "ERROR_EXPECTED" and not self.expect_sqlstate:
            raise ValueError("ERROR_EXPECTED requires 'expect_sqlstate'.")
        if self.expected != "ERROR_EXPECTED" and self.expect_sqlstate:
            raise ValueError("'expect_sqlstate' is only valid with expected: ERROR_EXPECTED.")
        if self.expected == "NO_ROWS" and op in ("INSERT",):
            raise ValueError("NO_ROWS is not meaningful for INSERT.")
        return self


class PrivilegeExpectation(_Strict):
    id: IdStr | None = None
    role: RoleName
    table: str
    allow: list[Literal["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]] = Field(default_factory=list)
    deny: list[Literal["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]] = Field(default_factory=list)


class Execution(_Strict):
    environment: Literal["disposable"] = "disposable"
    max_statements: int = Field(default=100, ge=1, le=5000)
    statement_timeout_ms: int = Field(default=1500, ge=50, le=30000)
    parallelism: int = Field(default=2, ge=1, le=8)
    allow_mutations: bool = True


class Spec(_Strict):
    version: Literal[1] = 1
    project: str = Field(min_length=1, max_length=120)
    source: SourceRef = Field(default_factory=SourceRef)
    identity_mode: IdentityMode = "postgres_roles"
    actors: list[Actor] = Field(min_length=1)
    tenants: list[Tenant] = Field(default_factory=list)
    resources: list[Resource] = Field(default_factory=list)
    tables: list[TableConfig] = Field(default_factory=list)
    expectations: list[Expectation] = Field(default_factory=list)
    privileges: list[PrivilegeExpectation] = Field(default_factory=list)
    execution: Execution = Field(default_factory=Execution)

    @field_validator("project")
    @classmethod
    def _proj(cls, v: str) -> str:
        return v.strip()

    # ---- lookups used throughout the engine ----
    def actor(self, actor_id: str):
        return next((a for a in self.actors if a.id == actor_id), None)

    def resource(self, rid: str):
        return next((r for r in self.resources if r.id == rid), None)

    def table_config(self, table: str):
        return next((t for t in self.tables if t.table == table), None)

    def tenant_value(self, tenant_id: str) -> Scalar:
        t = next((t for t in self.tenants if t.id == tenant_id), None)
        return t.value if t is not None and t.value is not None else tenant_id
