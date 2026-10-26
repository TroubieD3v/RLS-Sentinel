#!/usr/bin/env python3
"""Validate SARIF file(s) against the official SARIF 2.1.0 JSON Schema bundled with rls-sentinel.

Usage: python scripts/validate_sarif.py results.sarif [more.sarif ...]
Exit 0 when every file is valid, 1 otherwise.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema
import rls_sentinel.reporting.exporters as exporters


def main(paths: list[str]) -> int:
    if not paths:
        print(__doc__)
        return 2
    schema = json.loads(Path(exporters.SARIF_SCHEMA_PATH).read_text(encoding="utf-8"))
    bad = 0
    for p in paths:
        doc = json.loads(Path(p).read_text(encoding="utf-8"))
        errors = sorted(jsonschema.Draft7Validator(schema).iter_errors(doc), key=lambda e: list(e.path))
        if errors:
            bad += 1
            print(f"INVALID {p}")
            for e in errors[:10]:
                print(f"  {'/'.join(map(str, e.path)) or '<root>'}: {e.message[:200]}")
        else:
            n = sum(len(r.get("results", [])) for r in doc.get("runs", []))
            print(f"valid   {p} (SARIF {doc.get('version')}, {n} result(s))")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
