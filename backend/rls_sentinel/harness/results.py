"""Result contract for behavioral test runs (spec section 10.3 / 10.4)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Status = Literal["PASS", "FAIL", "INCONCLUSIVE", "ERROR", "UNSUPPORTED", "SKIPPED"]
FindingClass = Literal[
    "CONFIRMED_VIOLATION", "CONFIGURATION_RISK", "INCONCLUSIVE", "EXPECTED_DENIAL", "VERIFIED_ALLOW", "UNSUPPORTED",
]
Observed = Literal[
    "ROW_RETURNED", "ROWS_AFFECTED", "ROW_INSERTED", "NO_ROWS", "RLS_VIOLATION", "GRANT_DENIED",
    "POLICY_DEPENDENCY_ERROR", "POLICY_ERROR", "CONSTRAINT_ERROR", "SQL_ERROR", "TIMEOUT", "INFRA_ERROR", "NOT_EXECUTED",
]
Gate = Literal["GRANT", "RLS", "NONE", "UNKNOWN"]

ACCESS_OBSERVED = {"ROW_RETURNED", "ROWS_AFFECTED", "ROW_INSERTED"}


class PolicyHit(BaseModel):
    name: str
    command: str
    permissive: bool


class RawObservation(BaseModel):
    """What the database actually did, before comparison with any expectation."""

    model_config = ConfigDict(extra="forbid")

    observed: Observed = "NOT_EXECUTED"
    sqlstate: str | None = None
    message: str | None = None  # primary message only, sanitized; never contains row data
    row_count: int | None = None
    affected_pk_masked: list[str] = Field(default_factory=list)
    gate: Gate = "UNKNOWN"
    sql_display: str = ""
    session_user: str | None = None
    current_user: str | None = None
    role_superuser: bool | None = None
    role_bypassrls: bool | None = None
    table_owner_effective: bool | None = None
    rls_enabled: bool | None = None
    rls_forced: bool | None = None
    rls_applies: bool | None = None
    bypass_reason: str | None = None  # SUPERUSER | BYPASSRLS | TABLE_OWNER | None
    row_security_setting: str | None = None
    privilege_ok: bool | None = None  # has_table_privilege / column privilege for this operation
    applicable_policies: list[PolicyHit] = Field(default_factory=list)
    duration_ms: float | None = None
    precondition_failed: str | None = None


class Baseline(BaseModel):
    target_exists: bool | None = None  # established by the fixture admin, independent of RLS
    authorized_control: str | None = None  # id of an ALLOW SELECT expectation for the same resource
    authorized_control_status: str | None = None


class CaseEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    record_identifier_masked: bool = True
    row_contents_retained: bool = False
    observed_count: int | None = None
    environment_hash: str = ""
    identity_adapter: str = "postgres_roles"
    authentication_verified: bool = False
    sql: str = ""
    raw: RawObservation = Field(default_factory=RawObservation)
    baseline: Baseline = Field(default_factory=Baseline)
    explanation: str = ""
    notes: list[str] = Field(default_factory=list)


class CaseResult(BaseModel):
    case_id: str
    environment: str = "disposable-postgres"
    actor: str
    db_role: str
    resource: str | None = None
    table: str | None = None
    operation: str
    expected: str
    observed: str = "NOT_EXECUTED"
    status: Status
    finding_class: FindingClass
    sqlstate: str | None = None
    gate: Gate = "UNKNOWN"
    rule_hint: str | None = None
    violation_kind: str | None = None
    via: str | None = None
    columns: list[str] = Field(default_factory=list)
    moves_tenant: bool = False
    tenant_actor: str | None = None
    tenant_resource: str | None = None
    tags: list[str] = Field(default_factory=list)
    description: str = ""
    reason: str = ""
    evidence: CaseEvidence = Field(default_factory=CaseEvidence)
    started_at: datetime | None = None
    duration_ms: float | None = None


class CoverageSummary(BaseModel):
    expected_assertions: int = 0
    executed_valid_context: int = 0
    passed: int = 0
    failed: int = 0
    inconclusive: int = 0
    errors: int = 0
    unsupported: int = 0
    skipped: int = 0
    not_executed: int = 0
    decided: int = 0
    verified_coverage_pct: float = 0.0
    rls_exercised: int = 0
    grant_gate_only: int = 0
    synthetic_identity_cases: int = 0
    notes: list[str] = Field(default_factory=list)

    @classmethod
    def from_cases(cls, cases: list[CaseResult], *, total: int | None = None) -> CoverageSummary:
        c = cls(expected_assertions=total if total is not None else len(cases))
        for r in cases:
            if r.status == "PASS":
                c.passed += 1
            elif r.status == "FAIL":
                c.failed += 1
            elif r.status == "INCONCLUSIVE":
                c.inconclusive += 1
            elif r.status == "ERROR":
                c.errors += 1
            elif r.status == "UNSUPPORTED":
                c.unsupported += 1
            elif r.status == "SKIPPED":
                c.skipped += 1
            if r.gate == "RLS" and r.status in ("PASS", "FAIL"):
                c.rls_exercised += 1
            if r.gate == "GRANT":
                c.grant_gate_only += 1
            if r.evidence.identity_adapter != "postgres_roles":
                c.synthetic_identity_cases += 1
        c.executed_valid_context = c.passed + c.failed + c.inconclusive
        c.not_executed = c.errors + c.unsupported + c.skipped + max(0, c.expected_assertions - len(cases))
        c.decided = c.passed + c.failed
        c.verified_coverage_pct = round(100.0 * c.decided / c.expected_assertions, 1) if c.expected_assertions else 0.0
        return c

    def panel(self) -> str:
        w = 50
        rows = [
            ("Expected assertions", self.expected_assertions),
            ("Executed with valid context", self.executed_valid_context),
            ("PASS", self.passed),
            ("FAIL", self.failed),
            ("INCONCLUSIVE", self.inconclusive),
            ("NOT EXECUTED", self.not_executed),
        ]
        lines = ["AUTHORIZATION COVERAGE", "─" * w]
        lines += [f"{k:<28}: {v:>4}" for k, v in rows]
        lines.append(f"{'Verified coverage':<28}: {self.verified_coverage_pct:.1f}% ({self.decided} / {self.expected_assertions})")
        lines.append("─" * w)
        lines.append("Verified coverage = (PASS + FAIL) / expected assertions. INCONCLUSIVE, ERROR,")
        lines.append("UNSUPPORTED and SKIPPED cases are never counted as verified.")
        return "\n".join(lines)


class RunInfo(BaseModel):
    run_id: str
    project: str
    fixture: str | None = None
    variant: str | None = None
    environment_mode: str = "DISPOSABLE LAB"
    postgres_version: str = ""
    server_kind: str = ""
    spec_checksum: str = ""
    fixture_fingerprint: str = ""
    schema_hash: str = ""
    tool_version: str = ""
    ruleset_version: str = ""
    identity_mode: str = "postgres_roles"
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    status: Literal["queued", "running", "completed", "failed", "cancelled"] = "running"
    duration_s: float | None = None
    parallelism: int = 1


class IsolationProof(BaseModel):
    """Evidence that the lab left no persistent drift and never touched a source database."""

    data_digest_before: str = ""
    data_digest_after: str = ""
    no_fixture_drift: bool | None = None
    source_database_touched: bool = False
    harness_superuser: bool | None = None
    harness_bypassrls: bool | None = None
    statements_executed: int = 0


class RunResult(BaseModel):
    format: str = "rls-sentinel-run/1"
    info: RunInfo
    cases: list[CaseResult] = Field(default_factory=list)
    coverage: CoverageSummary = Field(default_factory=CoverageSummary)
    isolation: IsolationProof = Field(default_factory=IsolationProof)
    findings: list[dict[str, Any]] = Field(default_factory=list)  # serialized Finding objects
    snapshot: dict[str, Any] | None = None  # serialized catalog Snapshot (for the same fixture)
    spec: dict[str, Any] | None = None
    errors: list[str] = Field(default_factory=list)
