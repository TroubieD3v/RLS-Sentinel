"""Helpers made fast for large schemas must still return exactly what the slow versions did."""
from __future__ import annotations

from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from rls_sentinel.catalog.migrations import locate_objects
from rls_sentinel.catalog.models import CoverageManifest, PolicyRec, Snapshot, SourceInfo, TableRec
from rls_sentinel.redaction import MASK, redact_text

SECRETS = [
    "postgresql://u:Pa55w0rd@db/x", "password=hunter2", "PWD: abc", "api_key=xyz", "token: tkn123",
    "Bearer abcdefghijklmnopqrstu", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl",
    "sk_live_abcdefghijklmnop", "AKIAABCDEFGHIJKLMNOP", "ghp_" + "a" * 36, "service_role=abc",
]


def test_fast_path_still_masks_every_secret_shape():
    for s in SECRETS:
        assert MASK in redact_text(f"context {s} more"), s


@settings(max_examples=300, deadline=None)
@given(st.text(alphabet=st.characters(codec="utf-8"), max_size=80))
def test_text_without_trigger_words_is_unchanged_and_never_crashes(txt):
    out = redact_text(txt)
    if MASK not in out:
        assert out == txt


def _snap(n: int) -> Snapshot:
    return Snapshot(
        tool_version="test", ruleset_version="test", source=SourceInfo(kind="fixture", alias="t"),
        postgres_version="18", postgres_version_num=180000, database="d",
        tables=[TableRec(schema="public", name=f"t{i}", kind="table", owner="o") for i in range(n)],
        policies=[PolicyRec(name=f"p{i}", table=f"public.t{i % 3}", command="SELECT", roles=["r"], permissive=True) for i in range(9)],
        coverage=CoverageManifest(postgres_version="18", scan_mode="catalog_read_only"),
    )


def test_snapshot_indexes_follow_list_changes():
    s = _snap(3)
    assert s.table("public.t2").name == "t2"
    assert len(s.policies_for("public.t0")) == 3
    s.tables.append(TableRec(schema="public", name="late", kind="table", owner="o"))
    assert s.table("public.late") is not None
    s.policies = [p for p in s.policies if p.name != "p0"]
    assert [p.name for p in s.policies_for("public.t0")] == ["p3", "p6"]
    assert s.table("public.missing") is None


def test_migration_line_numbers(tmp_path: Path):
    sql = "-- header\n\nCREATE TABLE a (id int);\n-- c\nCREATE POLICY p ON a USING (true);\n\n\nCREATE VIEW v AS SELECT 1;\n"
    f = tmp_path / "m.sql"
    f.write_text(sql, encoding="utf-8")
    loc = locate_objects([f], tmp_path)
    assert loc["table:public.a"] == ("m.sql", 3)
    assert loc["policy:public.a:p"] == ("m.sql", 5)
    assert loc["table:public.v"] == ("m.sql", 8)
