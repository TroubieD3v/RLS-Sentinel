#!/usr/bin/env python3
"""Measure RLS Sentinel against the bundled fixtures and compare every case with the documented expectation.

For each fixture and variant this runs `rls-sentinel test` (a real PostgreSQL server, no mocks), then checks each
case's status against `expected_outcomes` in the fixture manifest. Those expectations were derived by hand from the
policy text (and, for `external-benchmark`, from the PostgreSQL documentation), not from this tool's output.

Output is a JSON document plus a Markdown table. It reports agreement counts and wall-clock time only. It makes no
claim about detection rates on real-world databases: the fixtures are small, synthetic and known to the author.

Usage:  python scripts/benchmark.py [--bin rls-sentinel] [--repeat 3] [--json out.json] [--md out.md]
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"


def run_cli(binary: str, fixture: str, variant: str, out: Path) -> tuple[dict, float]:
    env = {**os.environ, "PYTHONUTF8": "1"}
    t0 = time.perf_counter()
    proc = subprocess.run(
        [binary, "test", "--fixture", fixture, "--variant", variant, "--format", "json", "-q", "-o", str(out), "--fail-on", "none"],
        capture_output=True, text=True, env=env, cwd=ROOT, check=False,
    )
    wall = time.perf_counter() - t0
    if not out.is_file():
        raise SystemExit(f"{fixture}/{variant}: no report produced (exit {proc.returncode})\n{proc.stderr[-800:]}")
    return json.loads(out.read_text(encoding="utf-8")), wall


def compare(manifest: dict, variant: str, cases: list[dict]) -> dict:
    exp = (manifest.get("expected_outcomes") or {}).get(variant, {})
    exp_fail, exp_inc = set(exp.get("fail", [])), set(exp.get("inconclusive", []))
    agree, disagree = 0, []
    for c in cases:
        want = "FAIL" if c["case_id"] in exp_fail else "INCONCLUSIVE" if c["case_id"] in exp_inc else "PASS"
        if c["status"] == want:
            agree += 1
        else:
            disagree.append({"case": c["case_id"], "expected": want, "observed": c["status"]})
    missing = sorted((exp_fail | exp_inc) - {c["case_id"] for c in cases})
    return {"cases": len(cases), "agree": agree, "disagree": disagree, "documented_cases_not_found": missing}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bin", default="rls-sentinel")
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--json", type=Path)
    ap.add_argument("--md", type=Path)
    a = ap.parse_args()

    rows: list[dict] = []
    with tempfile.TemporaryDirectory() as td:
        for fx_dir in sorted(p for p in FIXTURES.iterdir() if (p / "fixture.yaml").is_file()):
            manifest = yaml.safe_load((fx_dir / "fixture.yaml").read_text(encoding="utf-8"))
            for variant in ("vulnerable", "secure"):
                walls, engine, last = [], [], {}
                for i in range(a.repeat):
                    rep, wall = run_cli(a.bin, fx_dir.name, variant, Path(td) / f"{fx_dir.name}-{variant}-{i}.json")
                    walls.append(wall)
                    engine.append(rep["info"]["duration_s"])
                    last = rep
                cmp = compare(manifest, variant, last["cases"])
                cov = last["coverage"]
                rows.append({
                    "fixture": fx_dir.name, "variant": variant, "postgres": last["info"]["postgres_version"],
                    "cases": cmp["cases"], "pass": cov["passed"], "fail": cov["failed"], "inconclusive": cov["inconclusive"],
                    "error": cov["errors"], "verified_coverage_pct": cov["verified_coverage_pct"],
                    "agree_with_documented": cmp["agree"], "disagreements": cmp["disagree"],
                    "documented_cases_not_found": cmp["documented_cases_not_found"],
                    "no_fixture_drift": last["isolation"]["no_fixture_drift"],
                    "engine_s_median": round(statistics.median(engine), 2), "wall_s_median": round(statistics.median(walls), 2),
                    "repeats": a.repeat,
                })
                print(f"{fx_dir.name:20} {variant:10} {cmp['agree']}/{cmp['cases']} agree  engine {rows[-1]['engine_s_median']}s  wall {rows[-1]['wall_s_median']}s", file=sys.stderr)

    meta = {"machine": platform.platform(), "python": platform.python_version(), "cpu_count": os.cpu_count(),
            "tool": subprocess.run([a.bin, "version"], capture_output=True, text=True, check=False).stdout.strip()}
    doc = {"meta": meta, "rows": rows}
    if a.json:
        a.json.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    lines = ["| Fixture | Variant | PostgreSQL | Cases | Pass | Fail | Inconclusive | Agree with documented | Engine s (median) | Wall s (median) |",
             "|---|---|---|---:|---:|---:|---:|---:|---:|---:|"]
    for r in rows:
        lines.append(f"| {r['fixture']} | {r['variant']} | {r['postgres']} | {r['cases']} | {r['pass']} | {r['fail']} | {r['inconclusive']} | "
                     f"{r['agree_with_documented']}/{r['cases']} | {r['engine_s_median']} | {r['wall_s_median']} |")
    md = "\n".join(lines)
    if a.md:
        a.md.write_text(md + "\n", encoding="utf-8")
    print(md)
    bad = [r for r in rows if r["disagreements"] or r["documented_cases_not_found"]]
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
