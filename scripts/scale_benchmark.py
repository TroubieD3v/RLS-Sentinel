#!/usr/bin/env python3
"""Measure RLS Sentinel on large generated schemas (hundreds of tables, thousands of policies).

For each requested size it generates a synthetic multi-tenant schema, provisions it in a disposable PostgreSQL,
and times every phase of a real run separately: provisioning, catalog snapshot, behavioural tests, rule engine,
access graph, matrix, reports, snapshot diff and storing the result in the metadata store.

Every table gets 4 policies for its tenant (SELECT/INSERT/UPDATE/DELETE), one restrictive policy, and filler
policies for unrelated roles up to --policies-per-table. Every 25th table has a planted "USING (true)" SELECT leak
and every 40th a "WITH CHECK (true)" INSERT leak, so the run also checks that the expected number of violations is
found at scale (correctness, not only speed).

Usage (from the repository root, with the backend installed):
    python scripts/scale_benchmark.py --tables 50 200 500 --policies-per-table 10 [--json out.json] [--md out.md]
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from typing import Any

from rls_sentinel.catalog.migrations import attach_migration_locations
from rls_sentinel.config import load_settings
from rls_sentinel.diff.snapshot_diff import diff_snapshots
from rls_sentinel.expectations.models import Spec
from rls_sentinel.graph.builder import build_graph, subgraph
from rls_sentinel.harness.fixtures import load_fixture, provision_fixture
from rls_sentinel.harness.runner import run_spec, scan_fixture_snapshot
from rls_sentinel.harness.servers import start_server
from rls_sentinel.persistence.repo import Database
from rls_sentinel.reporting.builder import build_report
from rls_sentinel.reporting.exporters import render
from rls_sentinel.reporting.matrix import build_matrix
from rls_sentinel.rules.engine import evaluate

AUDITORS = [f"sc_aud{i}" for i in range(5)]
SELECT_LEAK_EVERY, INSERT_LEAK_EVERY = 25, 40


def generate(root: Path, tables: int, per_table: int) -> tuple[dict[str, Any], int]:
    """Write the fixture SQL and return (spec dict, expected number of FAIL cases)."""
    (root / "sql").mkdir(parents=True)
    (root / "specs").mkdir()
    roles = ["sc_owner", "sc_app", "sc_alpha", "sc_beta", *AUDITORS]
    (root / "sql" / "00_roles.sql").write_text(
        "".join(f"CREATE ROLE {r} NOLOGIN;\n" for r in roles)
        + "GRANT sc_app TO sc_alpha, sc_beta;\nGRANT USAGE, CREATE ON SCHEMA public TO sc_owner;\nGRANT USAGE ON SCHEMA public TO sc_app;\n",
        encoding="utf-8")
    schema, policies, seed = ["SET ROLE sc_owner;\n"], ["SET ROLE sc_owner;\n"], []
    expected_fail = 0
    for i in range(tables):
        t = f"t{i:04d}"
        schema.append(f"CREATE TABLE {t} (id int PRIMARY KEY, tenant_id text NOT NULL, body text NOT NULL, "
                      f"archived boolean NOT NULL DEFAULT false);\nALTER TABLE {t} ENABLE ROW LEVEL SECURITY;\n"
                      f"GRANT SELECT, INSERT, UPDATE, DELETE ON {t} TO sc_app;\n")
        own = "tenant_id = current_user"
        sel = "true" if i % SELECT_LEAK_EVERY == 0 else own
        ins = "true" if i % INSERT_LEAK_EVERY == 0 else own
        expected_fail += (i % SELECT_LEAK_EVERY == 0) + (i % INSERT_LEAK_EVERY == 0)
        policies.append(
            f"CREATE POLICY {t}_sel ON {t} FOR SELECT TO sc_app USING ({sel});\n"
            f"CREATE POLICY {t}_ins ON {t} FOR INSERT TO sc_app WITH CHECK ({ins});\n"
            f"CREATE POLICY {t}_upd ON {t} FOR UPDATE TO sc_app USING ({own}) WITH CHECK ({own});\n"
            f"CREATE POLICY {t}_del ON {t} FOR DELETE TO sc_app USING ({own});\n"
            f"CREATE POLICY {t}_live ON {t} AS RESTRICTIVE FOR ALL TO sc_app USING (NOT archived);\n")
        for k in range(max(0, per_table - 5)):
            policies.append(f"CREATE POLICY {t}_aud{k} ON {t} FOR SELECT TO {AUDITORS[k % len(AUDITORS)]} "
                            f"USING (body <> 'hidden-{k}');\n")
        seed.append(f"INSERT INTO {t} (id, tenant_id, body) VALUES (1, 'sc_alpha', 'synthetic a'), (2, 'sc_beta', 'synthetic b');\n")
    schema.append("RESET ROLE;\n")
    policies.append("RESET ROLE;\n")
    (root / "sql" / "10_schema.sql").write_text("".join(schema), encoding="utf-8")
    (root / "sql" / "20_policies_secure.sql").write_text("".join(policies), encoding="utf-8")
    (root / "sql" / "30_seed.sql").write_text("".join(seed), encoding="utf-8")
    (root / "specs" / "sentinel.yaml").write_text("version: 1\nproject: scale\nactors: [{id: a, pg_role: sc_alpha}]\n", encoding="utf-8")
    (root / "fixture.yaml").write_text(
        "name: scale-benchmark\ntitle: Generated scale benchmark (synthetic)\nmin_pg_major: 15\n"
        f"roles: [{', '.join(roles)}]\n"
        "variants:\n  secure: [sql/00_roles.sql, sql/10_schema.sql, sql/20_policies_secure.sql, sql/30_seed.sql]\n"
        "spec: specs/sentinel.yaml\n", encoding="utf-8")

    spec: dict[str, Any] = {
        "version": 1, "project": f"scale-{tables}",
        "tenants": [{"id": "alpha", "value": "sc_alpha"}, {"id": "beta", "value": "sc_beta"}],
        "actors": [{"id": "alice", "pg_role": "sc_alpha", "tenant": "alpha"}, {"id": "bob", "pg_role": "sc_beta", "tenant": "beta"}],
        "resources": [], "tables": [], "expectations": [],
        "execution": {"max_statements": 5000, "parallelism": 4, "statement_timeout_ms": 5000},
    }
    for i in range(tables):
        t = f"public.t{i:04d}"
        spec["tables"].append({"table": t, "tenant_column": "tenant_id", "touch_column": "body"})
        spec["resources"].append({"id": f"a{i}", "table": t, "pk": {"id": 1}, "tenant": "alpha"})
        spec["expectations"] += [
            {"id": f"alice-reads-own-{i}", "actor": "alice", "operation": "SELECT", "resource": f"a{i}", "expected": "ALLOW"},
            {"id": f"bob-cannot-read-alpha-{i}", "actor": "bob", "operation": "SELECT", "resource": f"a{i}", "expected": "DENY"},
            {"id": f"bob-cannot-update-alpha-{i}", "actor": "bob", "operation": "UPDATE", "resource": f"a{i}", "set": {"body": "x"}, "expected": "DENY"},
            {"id": f"bob-cannot-insert-into-alpha-{i}", "actor": "bob", "operation": "INSERT", "table": t,
             "row": {"id": 1000 + i, "tenant_id": "sc_alpha", "body": "forged"}, "expected": "DENY"},
        ]
    return spec, expected_fail


def timed(phases: dict[str, float], name: str, fn: Any) -> Any:
    t0 = time.perf_counter()
    out = fn()
    phases[name] = round(time.perf_counter() - t0, 3)
    return out


def measure(tables: int, per_table: int, track_memory: bool) -> dict[str, Any]:
    settings = load_settings()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td) / "fixture"
        spec_dict, expected_fail = generate(root, tables, per_table)
        spec = Spec.model_validate(spec_dict)
        fx = load_fixture(root)
        phases: dict[str, float] = {}
        server = timed(phases, "start_server", lambda: start_server(settings))
        if track_memory:
            tracemalloc.start()
        try:
            fdb = timed(phases, "provision", lambda: provision_fixture(server, fx, "secure", trusted=True))
            try:
                snap = timed(phases, "catalog_snapshot", lambda: scan_fixture_snapshot(fdb))
                timed(phases, "migration_locations", lambda: attach_migration_locations(snap, fx.sql_files("secure"), fx.path))
                result = timed(phases, "behavioural_tests", lambda: run_spec(fdb, spec, snapshot=snap))
            finally:
                timed(phases, "teardown", fdb.teardown)
            result.snapshot = snap.model_dump(mode="json")
            findings = timed(phases, "rule_engine", lambda: evaluate(snap, spec, result))
            result.findings = [f.model_dump(mode="json") for f in findings]
            graph = timed(phases, "graph_build", lambda: build_graph(snap, spec, result, findings))
            timed(phases, "graph_subgraph", lambda: subgraph(graph, max_nodes=400))
            timed(phases, "matrix", lambda: build_matrix(result, spec))
            report = timed(phases, "report_model", lambda: build_report(result))
            for fmt in ("json", "html", "sarif"):
                timed(phases, f"render_{fmt}", lambda f=fmt: render(report, f))
            timed(phases, "snapshot_diff", lambda: diff_snapshots(snap, snap))
            db = Database(f"sqlite:///{(Path(td) / 'meta.db').as_posix()}")
            db.init()
            ws = db.default_workspace()["id"]

            def store() -> None:
                sid = db.save_snapshot(ws, snap)
                rid = db.create_run(ws, kind="lab", fixture=fx.name, variant="secure", job_id=None)
                db.complete_run(rid, result, sid)
            timed(phases, "store_result", store)
            db.dispose()
            peak = tracemalloc.get_traced_memory()[1] if track_memory else None
        finally:
            if track_memory:
                tracemalloc.stop()
            server.stop()
        cov = result.coverage
        return {
            "tables": tables, "policies": len(snap.policies), "roles": len([r for r in snap.roles if not r.system]),
            "cases": cov.expected_assertions, "passed": cov.passed, "failed": cov.failed, "inconclusive": cov.inconclusive,
            "errors": cov.errors, "expected_failed": expected_fail, "correct": cov.failed == expected_fail and cov.errors == 0,
            "findings": len(findings), "graph_nodes": len(graph.nodes), "graph_edges": len(graph.edges),
            "postgres": server.version, "server_kind": server.kind,
            "html_kib": round(len(render(report, "html")[0]) / 1024), "sarif_kib": round(len(render(report, "sarif")[0]) / 1024),
            "peak_python_mib": round(peak / 2**20, 1) if peak else None,
            "phases_s": phases, "total_s": round(sum(phases.values()), 2),
        }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tables", type=int, nargs="+", default=[50, 200, 500])
    ap.add_argument("--policies-per-table", type=int, default=10)
    ap.add_argument("--repeat", type=int, default=1, help="repeat each size and keep the median total")
    ap.add_argument("--memory", action="store_true", help="track peak Python allocations (slower)")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--md", type=Path)
    a = ap.parse_args()

    rows = []
    for n in a.tables:
        runs = [measure(n, a.policies_per_table, a.memory) for _ in range(a.repeat)]
        best = sorted(runs, key=lambda r: r["total_s"])[len(runs) // 2]
        best["total_s_all"] = [r["total_s"] for r in runs]
        rows.append(best)
        print(f"{n:5d} tables {best['policies']:6d} policies {best['cases']:5d} cases  total {best['total_s']}s  "
              f"failed {best['failed']}/{best['expected_failed']} expected  correct={best['correct']}", file=sys.stderr, flush=True)

    phases = list(rows[0]["phases_s"])
    lines = ["| Tables | Policies | Cases | Fail (expected) | " + " | ".join(phases) + " | Total s |",
             "|---:|---:|---:|---:|" + "---:|" * len(phases) + "---:|"]
    for r in rows:
        lines.append(f"| {r['tables']} | {r['policies']} | {r['cases']} | {r['failed']} ({r['expected_failed']}) | "
                     + " | ".join(str(r["phases_s"][p]) for p in phases) + f" | {r['total_s']} |")
    md = "\n".join(lines)
    print(md)
    meta = {"machine": platform.platform(), "python": platform.python_version(), "cpu_count": os.cpu_count(),
            "policies_per_table": a.policies_per_table, "repeat": a.repeat}
    if a.json:
        a.json.write_text(json.dumps({"meta": meta, "rows": rows}, indent=2), encoding="utf-8")
    if a.md:
        a.md.write_text(md + "\n", encoding="utf-8")
    return 0 if all(r["correct"] for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
