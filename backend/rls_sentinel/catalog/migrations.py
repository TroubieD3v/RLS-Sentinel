"""Attach migration-file provenance (path + line) to catalog objects, using the PostgreSQL parser (no regex).

Catalog state remains the source of truth; locations are only hints for reviewers and SARIF output.
"""

from __future__ import annotations

import bisect
import re
from pathlib import Path

from pglast import ast, parse_sql

from .models import Provenance, Snapshot


def _newline_offsets(text_bytes: bytes) -> list[int]:
    return [m.start() for m in re.finditer(b"\n", text_bytes)]


def _line_of(newlines: list[int], offset: int) -> int:
    """1-based line of a byte offset, given the sorted offsets of every newline (O(log n) per lookup)."""
    return bisect.bisect_left(newlines, max(offset, 0)) + 1


def _first_code_offset(text_bytes: bytes, start: int) -> int:
    """pglast statement locations include leading whitespace/comments of the previous gap; skip to first code byte."""
    i = start
    n = len(text_bytes)
    while i < n:
        if text_bytes[i : i + 2] == b"--":
            while i < n and text_bytes[i : i + 1] != b"\n":
                i += 1
        elif text_bytes[i : i + 1] in (b" ", b"\t", b"\r", b"\n"):
            i += 1
        else:
            break
    return i


def locate_objects(files: list[Path], base: Path) -> dict[str, tuple[str, int]]:
    """Return {object-key: (relative path, line)} for CREATE POLICY / TABLE / VIEW / FUNCTION statements."""
    out: dict[str, tuple[str, int]] = {}
    for f in files:
        data = f.read_bytes()
        try:
            stmts = parse_sql(data.decode("utf-8"))
        except Exception:  # noqa: S112 - unparsable migration files are skipped, never fatal
            continue
        rel = f.relative_to(base).as_posix() if base in f.parents or f.parent == base else f.name
        newlines = _newline_offsets(data)
        for raw in stmts:
            s = raw.stmt
            line = _line_of(newlines, _first_code_offset(data, raw.stmt_location))
            if isinstance(s, ast.CreatePolicyStmt):
                schema = s.table.schemaname or "public"
                out[f"policy:{schema}.{s.table.relname}:{s.policy_name}"] = (rel, line)
            elif isinstance(s, ast.CreateStmt):
                out[f"table:{s.relation.schemaname or 'public'}.{s.relation.relname}"] = (rel, line)
            elif isinstance(s, ast.ViewStmt):
                out[f"table:{s.view.schemaname or 'public'}.{s.view.relname}"] = (rel, line)
            elif isinstance(s, ast.CreateFunctionStmt):
                names = [n.sval for n in s.funcname]
                schema, name = (names[0], names[1]) if len(names) == 2 else ("public", names[0])
                out[f"function:{schema}.{name}"] = (rel, line)
    return out


def attach_migration_locations(snap: Snapshot, files: list[Path], base: Path) -> int:
    loc = locate_objects(files, base)
    n = 0
    for p in snap.policies:
        hit = loc.get(f"policy:{p.table}:{p.name}")
        if hit:
            p.provenance = Provenance(source="migration", ref=p.provenance.ref, path=hit[0], line=hit[1])
            n += 1
    for t in snap.tables:
        hit = loc.get(f"table:{t.qualified}")
        if hit:
            t.provenance = Provenance(source="migration", ref=t.provenance.ref, path=hit[0], line=hit[1])
            n += 1
    for fn in snap.functions:
        hit = loc.get(f"function:{fn.schema_name}.{fn.name}")
        if hit:
            fn.provenance = Provenance(source="migration", ref=fn.provenance.ref, path=hit[0], line=hit[1])
            n += 1
    return n
