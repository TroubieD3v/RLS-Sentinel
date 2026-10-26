"""Application metadata schema. Stores sanitized metadata and evidence only - never source row data or secrets."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, event
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

JSONType = JSON().with_variant(JSONB(), "postgresql")


def new_id() -> str:
    return uuid.uuid4().hex


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Workspace(Base):
    __tablename__ = "workspace"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ConnectionProfile(Base):
    __tablename__ = "connection_profile"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspace.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(24))  # live_source | fixture
    target_alias: Mapped[str] = mapped_column(String(120))
    mode: Mapped[str] = mapped_column(String(32))  # READ-ONLY SOURCE | DISPOSABLE LAB
    display_target: Mapped[str | None] = mapped_column(String(300), nullable=True)  # host:port/db - never credentials
    pg_major_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # "env:VAR_NAME" (read from the server environment at use time) or "session" (kept in process memory only).
    secret_ref: Mapped[str] = mapped_column(String(160), default="session")
    last_connection_status: Mapped[str | None] = mapped_column(String(300), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SnapshotRow(Base):
    __tablename__ = "snapshot"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspace.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    source_kind: Mapped[str] = mapped_column(String(24))
    source_alias: Mapped[str] = mapped_column(String(160), default="")
    mode: Mapped[str] = mapped_column(String(32), default="READ-ONLY SOURCE")
    schema_hash: Mapped[str] = mapped_column(String(80), index=True)
    coverage_json: Mapped[dict[str, Any]] = mapped_column(JSONType)
    postgres_version: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    data_json: Mapped[dict[str, Any]] = mapped_column(JSONType)  # full normalized snapshot (policy text redacted)
    objects: Mapped[list[CatalogObject]] = relationship(cascade="all, delete-orphan", passive_deletes=True)
    policies: Mapped[list[PolicyRecord]] = relationship(cascade="all, delete-orphan", passive_deletes=True)
    roles: Mapped[list[RoleRecord]] = relationship(cascade="all, delete-orphan", passive_deletes=True)
    memberships: Mapped[list[MembershipEdge]] = relationship(cascade="all, delete-orphan", passive_deletes=True)
    grants: Mapped[list[GrantRecord]] = relationship(cascade="all, delete-orphan", passive_deletes=True)


class CatalogObject(Base):
    __tablename__ = "catalog_object"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    snapshot_id: Mapped[str] = mapped_column(ForeignKey("snapshot.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(24), index=True)
    schema: Mapped[str] = mapped_column(String(80))
    qualified_name: Mapped[str] = mapped_column(String(300), index=True)
    owner: Mapped[str] = mapped_column(String(80), default="")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONType)


class PolicyRecord(Base):
    __tablename__ = "policy_record"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    snapshot_id: Mapped[str] = mapped_column(ForeignKey("snapshot.id", ondelete="CASCADE"), index=True)
    table_ref: Mapped[str] = mapped_column(String(300), index=True)
    name: Mapped[str] = mapped_column(String(120))
    command: Mapped[str] = mapped_column(String(12))
    roles: Mapped[list[str]] = mapped_column(JSONType)
    permissive: Mapped[bool] = mapped_column(Boolean)
    using_expression: Mapped[str | None] = mapped_column(Text, nullable=True)
    with_check_expression: Mapped[str | None] = mapped_column(Text, nullable=True)
    provenance_json: Mapped[dict[str, Any]] = mapped_column(JSONType)


class RoleRecord(Base):
    __tablename__ = "role_record"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    snapshot_id: Mapped[str] = mapped_column(ForeignKey("snapshot.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    attributes_json: Mapped[dict[str, Any]] = mapped_column(JSONType)


class MembershipEdge(Base):
    __tablename__ = "membership_edge"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    snapshot_id: Mapped[str] = mapped_column(ForeignKey("snapshot.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(80))
    member: Mapped[str] = mapped_column(String(80))
    inherit_option: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    set_option: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    admin_option: Mapped[bool] = mapped_column(Boolean, default=False)


class GrantRecord(Base):
    __tablename__ = "grant_record"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    snapshot_id: Mapped[str] = mapped_column(ForeignKey("snapshot.id", ondelete="CASCADE"), index=True)
    object_type: Mapped[str] = mapped_column(String(16))
    object_name: Mapped[str] = mapped_column(String(300), index=True)
    grantee: Mapped[str] = mapped_column(String(80))
    privilege: Mapped[str] = mapped_column(String(24))
    grantable: Mapped[bool] = mapped_column(Boolean, default=False)


class ExpectationSpecRow(Base):
    __tablename__ = "expectation_spec"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspace.id", ondelete="CASCADE"), index=True)
    project: Mapped[str] = mapped_column(String(120))
    version: Mapped[int] = mapped_column(Integer, default=1)
    validated_json: Mapped[dict[str, Any]] = mapped_column(JSONType)
    checksum: Mapped[str] = mapped_column(String(80), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TestRun(Base):
    __tablename__ = "test_run"
    __test__ = False  # not a pytest class
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspace.id", ondelete="CASCADE"), index=True)
    snapshot_id: Mapped[str | None] = mapped_column(ForeignKey("snapshot.id", ondelete="SET NULL"), nullable=True)
    expected_spec_id: Mapped[str | None] = mapped_column(ForeignKey("expectation_spec.id", ondelete="SET NULL"), nullable=True)
    job_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(16), default="lab")  # lab | whatif_sandbox
    fixture: Mapped[str | None] = mapped_column(String(80), nullable=True)
    variant: Mapped[str | None] = mapped_column(String(16), nullable=True)
    environment_mode: Mapped[str] = mapped_column(String(32), default="DISPOSABLE LAB")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="queued")
    version_info: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    coverage_json: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    result_json: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    cases: Mapped[list[TestCaseResultRow]] = relationship(cascade="all, delete-orphan", passive_deletes=True)


class TestCaseResultRow(Base):
    __tablename__ = "test_case_result"
    __test__ = False
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    run_id: Mapped[str] = mapped_column(ForeignKey("test_run.id", ondelete="CASCADE"), index=True)
    test_id: Mapped[str] = mapped_column(String(120))
    actor: Mapped[str] = mapped_column(String(120))
    resource: Mapped[str | None] = mapped_column(String(300), nullable=True)
    operation: Mapped[str] = mapped_column(String(12))
    expected: Mapped[str] = mapped_column(String(16))
    observed: Mapped[str] = mapped_column(String(32))
    result_status: Mapped[str] = mapped_column(String(16), index=True)
    sqlstate: Mapped[str | None] = mapped_column(String(5), nullable=True)
    environment_fingerprint: Mapped[str] = mapped_column(String(100), default="")
    evidence_ref: Mapped[dict[str, Any]] = mapped_column(JSONType)  # sanitized evidence bundle
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)


class FindingRow(Base):
    __tablename__ = "finding"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("test_run.id", ondelete="CASCADE"), index=True)
    workspace_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_id: Mapped[str] = mapped_column(String(12), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    evidence_class: Mapped[str] = mapped_column(String(24), index=True)
    subject: Mapped[str] = mapped_column(String(400))
    reason: Mapped[str] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(40), index=True)
    data_json: Mapped[dict[str, Any]] = mapped_column(JSONType)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (Index("ix_finding_run_rule", "run_id", "rule_id"),)


class FindingReview(Base):
    """Triage state keyed by stable fingerprint, so decisions survive re-runs."""

    __tablename__ = "finding_review"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(String(32), index=True)
    fingerprint: Mapped[str] = mapped_column(String(40), index=True)
    lifecycle_state: Mapped[str] = mapped_column(String(20), default="open")
    reviewer_note: Mapped[str] = mapped_column(Text, default="")
    reviewed_by: Mapped[str] = mapped_column(String(80), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Suppression(Base):
    __tablename__ = "suppression"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_id: Mapped[str] = mapped_column(String(12))
    scope: Mapped[str] = mapped_column(String(300), default="*")  # subject prefix or "*"
    reason: Mapped[str] = mapped_column(Text)
    owner: Mapped[str] = mapped_column(String(80))
    reviewer: Mapped[str] = mapped_column(String(80))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WhatIfExperimentRow(Base):
    __tablename__ = "whatif_experiment"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    workspace_id: Mapped[str] = mapped_column(String(32), index=True)
    baseline_run_id: Mapped[str] = mapped_column(ForeignKey("test_run.id", ondelete="CASCADE"), index=True)
    proposed_policy_diff: Mapped[str] = mapped_column(Text)
    sandbox_run_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resolved_findings: Mapped[int] = mapped_column(Integer, default=0)
    new_regressions: Mapped[int] = mapped_column(Integer, default=0)
    verdict: Mapped[str] = mapped_column(String(20), default="")
    status: Mapped[str] = mapped_column(String(16), default="queued")
    job_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    result_json: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class AuditEvent(Base):
    """Append-only. ORM-level UPDATE/DELETE is rejected (see listeners below); only the retention job may purge."""

    __tablename__ = "audit_event"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    workspace_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    actor: Mapped[str] = mapped_column(String(80))
    event_type: Mapped[str] = mapped_column(String(60), index=True)
    target: Mapped[str] = mapped_column(String(300), default="")
    detail_json: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class JobRow(Base):
    __tablename__ = "job"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    workspace_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(24))
    status: Mapped[str] = mapped_column(String(16), default="queued")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    progress_json: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    result_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class _AuditImmutable(Exception):
    pass


@event.listens_for(AuditEvent, "before_update")
def _block_update(mapper, connection, target):
    raise _AuditImmutable("audit events are immutable")


@event.listens_for(AuditEvent, "before_delete")
def _block_delete(mapper, connection, target):
    raise _AuditImmutable("audit events are immutable")
