"""Authorization matrix: actors x (operation, resource) built ONLY from executed cases (never guessed)."""

from __future__ import annotations

from typing import Any

from ..expectations.models import Spec
from ..harness.results import CaseResult, RunResult

STATE_LABEL = {
    "ALLOW_VERIFIED": "Expected ALLOW · observed ALLOW",
    "DENY_VERIFIED": "Expected DENY · observed DENY",
    "FAIL": "FAIL (expectation violated)",
    "UNKNOWN": "UNKNOWN (inconclusive / not executed)",
    "EXPECTED_ALLOW": "Expected ALLOW (not executed)",
    "EXPECTED_DENY": "Expected DENY (not executed)",
}


def cell_state(c: CaseResult) -> str:
    if c.status == "PASS":
        return "ALLOW_VERIFIED" if c.expected == "ALLOW" else "DENY_VERIFIED"
    if c.status == "FAIL":
        return "FAIL"
    return "UNKNOWN"


def column_key(c: CaseResult) -> str:
    target = c.via or c.resource or c.table or "?"
    cols = f"[{','.join(c.columns)}]" if c.columns else ""
    return f"{c.operation} {target}{cols}"


def build_matrix(run: RunResult, spec: Spec | None = None) -> dict[str, Any]:
    cols: dict[str, dict[str, Any]] = {}
    rows: dict[str, dict[str, Any]] = {}
    for c in run.cases:
        ck = column_key(c)
        cols.setdefault(ck, {"key": ck, "operation": c.operation, "table": c.table, "resource": c.resource, "via": c.via, "columns": c.columns,
                             "tenant": c.tenant_resource})
        row = rows.setdefault(c.actor, {"actor": c.actor, "db_role": c.db_role, "tenant": c.tenant_actor, "cells": {}})
        cell = {"case_id": c.case_id, "expected": c.expected, "observed": c.observed, "status": c.status, "state": cell_state(c),
                "gate": c.gate, "sqlstate": c.sqlstate, "finding_class": c.finding_class}
        row["cells"].setdefault(ck, []).append(cell)
    # expected-only cells when the matrix is shown for a not-yet-executed spec
    if spec is not None and not run.cases:
        for e in spec.expectations:
            res = spec.resource(e.resource) if e.resource else None
            ck = f"{e.operation} {e.via or e.resource or e.table}"
            cols.setdefault(ck, {"key": ck, "operation": e.operation, "table": e.table or (res.table if res else None), "resource": e.resource,
                                 "via": e.via, "columns": e.columns, "tenant": res.tenant if res else e.as_tenant})
            a = spec.actor(e.actor)
            row = rows.setdefault(e.actor, {"actor": e.actor, "db_role": a.pg_role if a else "", "tenant": a.tenant if a else None, "cells": {}})
            row["cells"].setdefault(ck, []).append({"case_id": e.id, "expected": e.expected, "observed": None, "status": "NOT_RUN",
                                                    "state": "EXPECTED_ALLOW" if e.expected == "ALLOW" else "EXPECTED_DENY"})
    order = {"user": 0, "support": 1, "service": 2, "admin": 3, "owner": 4, "anonymous": 5}
    kinds = {a.id: a.kind for a in spec.actors} if spec else {}
    row_list = sorted(rows.values(), key=lambda r: (order.get(kinds.get(r["actor"], "user"), 9), r["actor"]))
    col_list = sorted(cols.values(), key=lambda c: (c["table"] or "", c["operation"], c["key"]))
    totals: dict[str, int] = {}
    for r in row_list:
        for cells in r["cells"].values():
            for cell in cells:
                totals[cell["state"]] = totals.get(cell["state"], 0) + 1
    return {"rows": row_list, "columns": col_list, "totals": totals, "state_labels": STATE_LABEL,
            "executed": bool(run.cases), "denominator": run.coverage.expected_assertions}
