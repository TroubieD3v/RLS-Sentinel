"""Findings: the user-facing unit of evidence-backed security output."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

EvidenceClass = Literal[
    "CONFIRMED_VIOLATION", "CONFIGURATION_RISK", "INCONCLUSIVE", "EXPECTED_DENIAL", "VERIFIED_ALLOW", "UNSUPPORTED",
]
Severity = Literal["Critical", "High", "Medium", "Low", "Informational", "Needs triage"]
Provenance = Literal["CATALOG_FACT", "STATIC_INFERENCE", "RUNTIME_OBSERVATION", "USER_EXPECTATION"]
Confidence = Literal["OBSERVED", "ESTABLISHED", "CONDITIONAL", "ASSUMED"]
Lifecycle = Literal["open", "triaged", "accepted_risk", "false_positive", "fixed", "needs_info"]

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4, "Needs triage": 5}
CLASS_ORDER = {"CONFIRMED_VIOLATION": 0, "CONFIGURATION_RISK": 1, "INCONCLUSIVE": 2, "UNSUPPORTED": 3,
               "EXPECTED_DENIAL": 4, "VERIFIED_ALLOW": 5}


class EvidenceRef(BaseModel):
    kind: Literal["case", "catalog", "spec", "diff"]
    ref: str
    summary: str = ""
    provenance: Provenance = "CATALOG_FACT"


class Finding(BaseModel):
    id: str
    fingerprint: str
    rule_id: str
    title: str
    severity: Severity
    severity_rationale: str
    evidence_class: EvidenceClass
    provenance: list[Provenance] = Field(default_factory=list)
    confidence: Confidence = "ESTABLISHED"
    subject: str
    summary: str  # what happened
    why_it_matters: str = ""
    expected: str | None = None
    observed: str | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)
    case_ids: list[str] = Field(default_factory=list)
    objects: dict[str, Any] = Field(default_factory=dict)
    reproduction: list[str] = Field(default_factory=list)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    limitations: str = ""
    verified_by: Literal["runtime_lab", "catalog", "static_sql", "diff"] = "catalog"
    location: dict[str, Any] | None = None  # {"path":..., "line":...} when known
    lifecycle_state: Lifecycle = "open"
    reviewer_note: str = ""
    suppressed: bool = False
    suppression: dict[str, Any] | None = None
    related: list[str] = Field(default_factory=list)  # ids of linked findings (e.g. static risk confirmed at runtime)
    first_seen: datetime | None = None

    @property
    def is_runtime_proven(self) -> bool:
        return self.evidence_class == "CONFIRMED_VIOLATION" and "RUNTIME_OBSERVATION" in self.provenance


def make_fingerprint(rule_id: str, subject: str, *discriminators: str) -> str:
    h = hashlib.sha256("|".join([rule_id, subject, *discriminators]).encode()).hexdigest()
    return "fp1:" + h[:24]


def make_id(fingerprint: str, run_id: str | None = None) -> str:
    base = fingerprint if run_id is None else f"{fingerprint}:{run_id}"
    return "f_" + hashlib.sha256(base.encode()).hexdigest()[:12]
