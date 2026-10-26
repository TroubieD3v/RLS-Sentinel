"""Canonical machine-readable report assembled from a run. Every exporter starts from this structure."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .. import RULESET_VERSION, TOOL_NAME, __version__
from ..findings.models import CLASS_ORDER, SEVERITY_ORDER, Finding
from ..harness.results import RunResult
from ..redaction import redact_obj
from ..rules.registry import RULES
from .matrix import build_matrix

REPORT_FORMAT = "rls-sentinel-report/1"

LIMITATIONS = [
    "Results describe the tested schema in a disposable database with synthetic data; they are not proof that a production system is safe or unsafe.",
    "Static findings are hypotheses derived from catalog metadata; only findings marked RUNTIME_OBSERVATION were demonstrated by executing statements.",
    "Synthetic claim injection (supabase_synthetic) exercises policy logic only and never verifies application authentication.",
    "Unknown, inconclusive, skipped and unsupported cases are reported separately and never counted as verified.",
    "This report does not replace network controls, authentication, application authorization review or formal penetration testing.",
]


def _snapshot_summary(snap: dict[str, Any] | None) -> dict[str, Any] | None:
    if not snap:
        return None
    return {
        "postgres_version": snap.get("postgres_version"), "database": snap.get("database"), "schema_hash": snap.get("schema_hash"),
        "source": snap.get("source"), "coverage": snap.get("coverage"),
        "counts": {k: len(snap.get(k, [])) for k in ("schemas", "tables", "policies", "roles", "memberships", "grants", "functions")},
    }


def finding_sort_key(f: dict[str, Any] | Finding) -> tuple[int, int, str]:
    d = f if isinstance(f, dict) else f.model_dump()
    return (CLASS_ORDER.get(d["evidence_class"], 9), SEVERITY_ORDER.get(d["severity"], 9), d["rule_id"] + d["subject"])


def build_report(run: RunResult, findings: list[dict[str, Any]] | None = None, *, include_snapshot: bool = False,
                 spec_path: str | None = None, suppressions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    fs = sorted(findings if findings is not None else run.findings, key=finding_sort_key)
    visible = [f for f in fs if not f.get("suppressed")]
    suppressed = [f for f in fs if f.get("suppressed")]
    by_class: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for f in visible:
        by_class[f["evidence_class"]] = by_class.get(f["evidence_class"], 0) + 1
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    spec = run.spec
    rules_used = sorted({f["rule_id"] for f in fs})
    report: dict[str, Any] = {
        "format": REPORT_FORMAT,
        "generated_at": datetime.now(UTC).isoformat(),
        "tool": {"name": TOOL_NAME, "version": __version__, "ruleset": RULESET_VERSION},
        "scope": {
            "environment": run.info.environment_mode, "postgres_version": run.info.postgres_version, "server": run.info.server_kind,
            "fixture": run.info.fixture, "variant": run.info.variant, "identity_mode": run.info.identity_mode,
            "identity_adapter_note": ("SYNTHETIC identity context - not verified authentication" if run.info.identity_mode != "postgres_roles"
                                      else "PostgreSQL roles via SET ROLE from a non-superuser harness login"),
            "source_row_data_collected": False, "row_contents_retained": False,
        },
        "run": run.info.model_dump(mode="json"),
        "reproducibility": {"schema_hash": run.info.schema_hash, "spec_checksum": run.info.spec_checksum, "fixture_fingerprint": run.info.fixture_fingerprint,
                            "tool_version": __version__, "ruleset_version": RULESET_VERSION, "postgres_version": run.info.postgres_version},
        "coverage": run.coverage.model_dump(mode="json") | {"panel": run.coverage.panel()},
        "isolation": run.isolation.model_dump(mode="json"),
        "summary": {"findings_total": len(visible), "suppressed": len(suppressed), "by_evidence_class": by_class, "by_severity": by_sev,
                    "confirmed_violations": by_class.get("CONFIRMED_VIOLATION", 0), "configuration_risks": by_class.get("CONFIGURATION_RISK", 0),
                    "inconclusive": by_class.get("INCONCLUSIVE", 0), "cases_failed": run.coverage.failed,
                    "cases_inconclusive": run.coverage.inconclusive, "denominator": run.coverage.expected_assertions},
        "findings": visible,
        "suppressed_findings": [{"id": f["id"], "rule_id": f["rule_id"], "subject": f["subject"], "suppression": f.get("suppression")} for f in suppressed],
        "cases": [c.model_dump(mode="json") for c in run.cases],
        "matrix": build_matrix(run),
        "rules": {rid: {"title": RULES[rid].title, "references": list(RULES[rid].references)} for rid in rules_used if rid in RULES},
        "snapshot": _snapshot_summary(run.snapshot),
        "spec_path": spec_path,
        "limitations": LIMITATIONS,
        "errors": run.errors,
    }
    if include_snapshot:
        report["catalog_snapshot"] = run.snapshot
        report["spec"] = spec
    return redact_obj(report)
