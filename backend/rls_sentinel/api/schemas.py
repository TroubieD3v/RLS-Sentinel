"""Request bodies for the public API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class WorkspaceIn(_In):
    name: str = Field(min_length=1, max_length=120, examples=["acme-saas"])
    description: str = Field(default="", max_length=2000)


class ConnectionTestIn(_In):
    dsn: str | None = Field(default=None, max_length=2000, description="Write-only. Never stored, logged or returned.", examples=["postgresql://sentinel_ro@db.internal:5432/app"])
    secret_ref: str | None = Field(default=None, pattern=r"^env:[A-Za-z_][A-Za-z0-9_]*$", examples=["env:SENTINEL_DATABASE_URL"])


class ConnectionIn(ConnectionTestIn):
    workspace_id: str | None = None
    alias: str = Field(min_length=1, max_length=120)
    kind: Literal["live_source"] = "live_source"


class ScanIn(_In):
    workspace_id: str | None = None
    connection_id: str | None = None
    fixture: str | None = Field(default=None, description="Scan a disposable lab database instead of a live source.")
    variant: Literal["vulnerable", "secure"] | None = None
    schemas: list[str] | None = Field(default=None, max_length=50)
    allow_privileged: bool = False


class SpecValidateIn(_In):
    spec: str | None = Field(default=None, max_length=262144, description="YAML or JSON text.")
    spec_object: dict[str, Any] | None = None
    filename: str = "sentinel.yaml"
    snapshot_id: str | None = None


class TestRunIn(_In):
    __test__ = False
    workspace_id: str | None = None
    fixture: str = Field(min_length=1, max_length=200)
    variant: Literal["vulnerable", "secure"]
    spec: str | None = Field(default=None, max_length=262144, description="Optional spec text; defaults to the fixture's spec.")
    filename: str = "sentinel.yaml"
    only: list[str] | None = Field(default=None, max_length=200)


class WhatIfIn(_In):
    run_id: str
    draft_sql: str = Field(min_length=1, max_length=40000)


class WhatIfLintIn(_In):
    draft_sql: str = Field(min_length=1, max_length=40000)


class FindingReviewIn(_In):
    lifecycle_state: Literal["open", "triaged", "accepted_risk", "false_positive", "fixed", "needs_info"]
    reviewer_note: str = Field(default="", max_length=4000)


class SuppressionIn(_In):
    workspace_id: str | None = None
    rule_id: str = Field(pattern=r"^RLS-\d{3}$")
    scope: str = Field(default="*", max_length=300, description="'*' or a subject prefix such as public.invoices")
    reason: str = Field(min_length=10, max_length=2000)
    owner: str = Field(min_length=1, max_length=80)
    reviewer: str = Field(min_length=1, max_length=80)
    expires_at: datetime


class DiffIn(_In):
    from_run_id: str | None = None
    to_run_id: str | None = None
    from_snapshot_id: str | None = None
    to_snapshot_id: str | None = None
    from_json: dict[str, Any] | None = None
    to_json: dict[str, Any] | None = None


class PurgeIn(_In):
    days: int = Field(ge=1, le=3650)
