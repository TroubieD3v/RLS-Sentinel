"""`rls-sentinel scan` against a live database: read-only, no row data, refuses privileged accounts, never echoes secrets."""
from __future__ import annotations

import json

import psycopg
from typer.testing import CliRunner

from rls_sentinel.cli.main import app as cli_app
from rls_sentinel.harness.fixtures import load_fixture, provision_fixture

runner = CliRunner()


def _row_counts(dsn: str) -> dict[str, int]:
    with psycopg.connect(dsn) as c:
        tables = [r[0] for r in c.execute("SELECT format('%I.%I', schemaname, tablename) FROM pg_tables WHERE schemaname='public' ORDER BY 1")]
        return {t: c.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in tables}


def test_scan_is_read_only_and_collects_no_rows(settings, pg_server, tmp_path, monkeypatch):
    fx = load_fixture(settings.fixtures_dir / "multi-tenant-saas", bundled=True)
    with provision_fixture(pg_server, fx, "vulnerable") as db:
        with psycopg.connect(db.admin_dsn) as c:  # an unprivileged inspector, as an operator would create for a real audit
            c.execute("CREATE ROLE scan_inspector LOGIN PASSWORD 'inspector-pw-test'")
            c.execute(f'GRANT CONNECT ON DATABASE "{db.dbname}" TO scan_inspector')
            c.commit()
        db.created_roles.append("scan_inspector")
        host_port = db.admin_dsn.split("@", 1)[1]
        inspector_dsn = f"postgresql://scan_inspector:inspector-pw-test@{host_port}"
        before = _row_counts(db.admin_dsn)

        monkeypatch.setenv("SOURCE_DSN", inspector_dsn)
        out = tmp_path / "scan.json"
        host = host_port.split(":")[0].split("/")[0]
        r = runner.invoke(cli_app, ["scan", "--connection-env", "SOURCE_DSN", "--allow-target", host, "-o", str(out)])
        assert r.exit_code in (0, 1), r.output
        assert "inspector-pw-test" not in r.output

        rep = json.loads(out.read_text(encoding="utf-8"))
        assert rep["info"]["environment_mode"] == "READ-ONLY SOURCE"
        assert rep["coverage"]["executed_valid_context"] == 0  # no behavioural tests against a source, ever
        assert rep["snapshot"]["coverage"]["source_row_data_collected"] is False
        assert rep["snapshot"]["coverage"]["runtime_tests_executed"] == 0
        assert any(f["rule_id"].startswith("RLS-") for f in rep["findings"])  # static analysis still finds the planted defects
        assert all(f["evidence_class"] != "CONFIRMED_VIOLATION" for f in rep["findings"])  # static inference is never "confirmed"
        assert "inspector-pw-test" not in out.read_text(encoding="utf-8")

        assert _row_counts(db.admin_dsn) == before  # nothing was written or removed


def test_scan_refuses_a_superuser_inspector_by_default(settings, pg_server, monkeypatch):
    fx = load_fixture(settings.fixtures_dir / "multi-tenant-saas", bundled=True)
    with provision_fixture(pg_server, fx, "secure") as db:
        monkeypatch.setenv("SOURCE_DSN", db.admin_dsn)  # superuser of the disposable server
        host = db.admin_dsn.split("@", 1)[1].split(":")[0]
        r = runner.invoke(cli_app, ["scan", "--connection-env", "SOURCE_DSN", "--allow-target", host])
        assert r.exit_code != 0
        assert "privileged" in r.output.lower() or "superuser" in r.output.lower()
