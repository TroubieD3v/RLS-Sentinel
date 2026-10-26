"""``rls-sentinel`` command line interface.

Exit codes
  0  completed; no confirmed finding at/above the threshold; required coverage reached
  1  a confirmed (runtime-proven) violation meets the threshold
  2  invalid configuration or user request
  3  execution error, or required coverage not reached (inconclusive is never counted as safe)
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import webbrowser
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .. import RULESET_VERSION, __version__
from ..config import Settings, load_settings
from ..errors import SentinelError, SpecError
from ..expectations.loader import check_internal_references, load_spec, load_spec_text
from ..expectations.models import Spec
from ..findings.models import SEVERITY_ORDER, Finding
from ..harness.fixtures import discover_fixtures, find_fixture
from ..harness.results import RunResult
from ..redaction import install_log_masking, redact_text

EXIT_OK, EXIT_VIOLATION, EXIT_USAGE, EXIT_ERROR = 0, 1, 2, 3

app = typer.Typer(add_completion=False, no_args_is_help=True, rich_markup_mode="rich",
                  help="[bold]RLS Sentinel[/bold] - PostgreSQL Row-Level Security verification. [dim]DATABASE ACCESS. VERIFIED.[/dim]")
spec_app = typer.Typer(no_args_is_help=True, help="Expected-policy specification tools.")
fixtures_app = typer.Typer(no_args_is_help=True, help="Bundled synthetic fixtures.")
demo_app = typer.Typer(no_args_is_help=True, help="Local demo (no external credentials).")
app.add_typer(spec_app, name="spec")
app.add_typer(fixtures_app, name="fixtures")
app.add_typer(demo_app, name="demo")

try:  # Windows consoles default to legacy code pages
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
except Exception:  # noqa: S110
    pass
console = Console(highlight=False)
err = Console(stderr=True, highlight=False)

_SEV = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Informational", "none": "none"}
_STYLE = {"Critical": "bold red", "High": "red", "Medium": "yellow", "Low": "cyan", "Informational": "blue", "Needs triage": "magenta"}


def _die(msg: str, code: int = EXIT_USAGE) -> NoReturn:
    err.print(f"[bold red]error:[/bold red] {redact_text(msg)}")
    raise typer.Exit(code)


def _guard(fn):
    """Decorator mapping domain errors to exit codes."""
    import functools

    @functools.wraps(fn)
    def wrapper(*a: Any, **kw: Any):
        install_log_masking()
        try:
            return fn(*a, **kw)
        except typer.Exit:
            raise
        except SpecError as exc:
            err.print(f"[bold red]invalid:[/bold red] {redact_text(exc.message)}")
            for i in exc.issues[:20]:
                err.print(f"  - [{i.get('level', 'error')}] {i.get('path', '')}: {redact_text(str(i.get('message')))}")
            raise typer.Exit(EXIT_USAGE) from exc
        except SentinelError as exc:
            err.print(f"[bold red]error:[/bold red] {redact_text(exc.message)}")
            raise typer.Exit(EXIT_USAGE if exc.status in (400, 404, 409, 422) else EXIT_ERROR) from exc
        except KeyboardInterrupt:
            err.print("interrupted")
            raise typer.Exit(130) from None
        except Exception as exc:
            err.print(f"[bold red]execution error:[/bold red] {redact_text(type(exc).__name__ + ': ' + str(exc))[:400]}")
            raise typer.Exit(EXIT_ERROR) from exc

    return wrapper


def _write(path: Path | None, text: str) -> None:
    if path is None:
        sys.stdout.write(text)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _load_run(path: Path) -> RunResult:
    try:
        return RunResult.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SpecError(f"{path} is not an rls-sentinel run file: {str(exc)[:160]}") from exc


def _threshold(fail_on: str) -> int | None:
    v = fail_on.lower()
    if v == "none":
        return None
    if v not in _SEV:
        raise SpecError(f"--fail-on must be one of {', '.join(_SEV)}")
    return SEVERITY_ORDER[_SEV[v]]


def _print_findings(findings: list[dict[str, Any]], limit: int = 25) -> None:
    if not findings:
        console.print("[green]No findings.[/green]")
        return
    t = Table(title="Findings", show_lines=False, header_style="bold")
    for col in ("Sev", "Rule", "Evidence", "Subject / summary"):
        t.add_column(col, overflow="fold")
    for f in findings[:limit]:
        t.add_row(f"[{_STYLE.get(f['severity'], '')}]{f['severity']}[/]", f["rule_id"], f["evidence_class"].replace("_", " ").lower(),
                  redact_text(f["summary"])[:140])
    console.print(t)
    if len(findings) > limit:
        console.print(f"[dim]… {len(findings) - limit} more (see the output file)[/dim]")


def _print_run(res: RunResult) -> None:
    c = res.coverage
    console.print(Panel(c.panel(), title=f"{res.info.fixture or res.info.project} · {res.info.variant or ''} · PostgreSQL {res.info.postgres_version} · {res.info.environment_mode}",
                        border_style="green" if c.failed == 0 else "red"))
    bad = [x for x in res.cases if x.status in ("FAIL", "INCONCLUSIVE", "ERROR")]
    if bad:
        t = Table(title="Cases needing attention", header_style="bold")
        for col in ("Status", "Case", "Expected", "Observed", "Why"):
            t.add_column(col, overflow="fold")
        for x in bad[:30]:
            colour = {"FAIL": "red", "INCONCLUSIVE": "yellow", "ERROR": "magenta"}[x.status]
            t.add_row(f"[{colour}]{x.status}[/]", x.case_id, x.expected, x.observed, x.reason[:110])
        console.print(t)
    iso = res.isolation
    console.print(f"[dim]isolation: harness superuser={iso.harness_superuser} bypassrls={iso.harness_bypassrls} · no fixture drift={iso.no_fixture_drift} · "
                  f"source database touched={iso.source_database_touched}[/dim]")


def _exit_code(res: RunResult, *, fail_on: str, include_static: bool, min_coverage: float) -> int:
    thr = _threshold(fail_on)
    if res.info.status != "completed" or (res.errors and any(e.startswith(("Fixture drift", "SpecError")) for e in res.errors)):
        err.print("[red]run did not complete cleanly[/red]")
        return EXIT_ERROR
    if res.isolation.no_fixture_drift is False:
        err.print("[red]fixture drift detected: results are not trustworthy[/red]")
        return EXIT_ERROR
    findings = res.findings
    if thr is not None:
        for f in findings:
            if SEVERITY_ORDER.get(f["severity"], 9) <= thr and (f["evidence_class"] == "CONFIRMED_VIOLATION" or (include_static and f["evidence_class"] == "CONFIGURATION_RISK")):
                return EXIT_VIOLATION
    if res.coverage.verified_coverage_pct + 1e-9 < min_coverage:
        err.print(f"[yellow]required coverage not reached: {res.coverage.verified_coverage_pct}% < {min_coverage}% "
                  f"({res.coverage.inconclusive} inconclusive, {res.coverage.not_executed} not executed). Unknown is not safe.[/yellow]")
        return EXIT_ERROR
    return EXIT_OK


# ------------------------------------------------------------------------------------------------ meta
@app.command("version")
def version() -> None:
    """Print tool and ruleset versions."""
    console.print(f"rls-sentinel {__version__} (ruleset {RULESET_VERSION})")


@app.command("rules")
def rules_cmd() -> None:
    """List the rule catalogue."""
    from ..rules.registry import RULES

    t = Table(header_style="bold")
    for c in ("ID", "Title", "Category", "Static", "Runtime"):
        t.add_column(c, overflow="fold")
    for r in RULES.values():
        t.add_row(r.id, r.title, r.category, "yes" if r.supports_static else "-", "yes" if r.supports_runtime else "-")
    console.print(t)


# ------------------------------------------------------------------------------------------------ spec
@spec_app.command("validate")
@_guard
def spec_validate(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    json_out: Annotated[bool, typer.Option("--json", help="Machine-readable output")] = False,
) -> None:
    """Validate an expectation manifest (schema + references)."""
    spec = load_spec(path)
    issues = check_internal_references(spec)
    warnings = [i for i in issues if i["level"] == "warning"]
    if json_out:
        console.print_json(json.dumps({"valid": True, "project": spec.project, "actors": len(spec.actors), "expectations": len(spec.expectations), "warnings": warnings}))
    else:
        console.print(f"[green]✓ valid[/green] {path.name}: project [bold]{spec.project}[/bold], {len(spec.actors)} actors, {len(spec.resources)} resources, "
                      f"{len(spec.expectations)} expectations, {len(spec.privileges)} privilege checks")
        for w in warnings:
            console.print(f"[yellow]warning[/yellow] {w['path']}: {w['message']}")


@spec_app.command("schema")
def spec_schema(output: Annotated[Path | None, typer.Option("--output", "-o")] = None) -> None:
    """Print the JSON Schema of the specification."""
    _write(output, json.dumps(Spec.model_json_schema(), indent=2) + "\n")


# ------------------------------------------------------------------------------------------------ fixtures
@fixtures_app.command("list")
def fixtures_list() -> None:
    """List bundled fixtures."""
    s = load_settings()
    t = Table(header_style="bold")
    for c in ("Name", "Variants", "Description"):
        t.add_column(c, overflow="fold")
    for f in discover_fixtures(s.fixtures_dir):
        t.add_row(f.name, ", ".join(f.variants), f.title)
    console.print(t)


# ------------------------------------------------------------------------------------------------ test
@app.command("test")
@_guard
def test_cmd(
    fixture: Annotated[str, typer.Option("--fixture", help="Bundled fixture name or a fixture directory")],
    spec: Annotated[Path | None, typer.Option("--spec", help="Expected-policy manifest (default: the fixture's own)")] = None,
    variant: Annotated[str, typer.Option("--variant", help="vulnerable | secure | both")] = "vulnerable",
    format: Annotated[str, typer.Option("--format", help="json | sarif | html | md | csv")] = "json",
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Output file (stdout if omitted)")] = None,
    fail_on: Annotated[str, typer.Option("--fail-on", help="critical|high|medium|low|info|none: threshold for CONFIRMED violations")] = "low",
    include_static: Annotated[bool, typer.Option("--include-static", help="Also count static CONFIGURATION_RISK findings toward --fail-on")] = False,
    min_coverage: Annotated[float, typer.Option("--min-coverage", help="Required verified coverage % (PASS+FAIL over expected). Unknown is never safe.")] = 100.0,
    backend: Annotated[str | None, typer.Option("--backend", help="auto | local | docker | external")] = None,
    only: Annotated[list[str] | None, typer.Option("--only", help="Run only these expectation ids")] = None,
    trust_fixture: Annotated[bool, typer.Option("--trust-fixture", help="Allow a non-bundled fixture to run (it executes as superuser in the disposable server)")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q")] = False,
) -> None:
    """Run the authorization matrix against a [bold]disposable[/bold] PostgreSQL fixture. Never touches a source database."""
    from ..reporting.builder import build_report
    from ..reporting.exporters import render
    from ..service import run_fixture_test

    s = load_settings()
    fx = find_fixture(fixture, s.fixtures_dir)
    if not fx.bundled and not trust_fixture:
        _die(f"Fixture '{fx.name}' is not bundled. It would run SQL as superuser inside the disposable server; pass --trust-fixture to confirm you reviewed it.")
    variants = list(fx.variants) if variant == "both" else [variant]
    for v in variants:
        if v not in fx.variants:
            _die(f"Fixture '{fx.name}' has no variant '{v}' (available: {', '.join(fx.variants)}).")
    custom = load_spec(spec) if spec else None
    from ..harness.servers import start_server

    server = start_server(s, backend=backend)
    worst = EXIT_OK
    results: list[RunResult] = []
    try:
        for v in variants:
            if not quiet:
                err.print(f"[dim]provisioning disposable {server.kind} PostgreSQL {server.version} · fixture {fx.name}:{v}[/dim]")
            res, _snap = run_fixture_test(s, fx, v, spec=custom, server=server, only=only, trusted=True if trust_fixture else None,
                                          progress=None if quiet else (lambda e: None))
            results.append(res)
            if not quiet:
                _print_run(res)
                _print_findings([f for f in res.findings if f["evidence_class"] == "CONFIRMED_VIOLATION"])
            worst = max(worst, _exit_code(res, fail_on=fail_on, include_static=include_static, min_coverage=min_coverage), key=lambda c: {0: 0, 1: 1, 3: 2, 2: 3}[c])
    finally:
        server.stop()
    if len(results) == 1:
        res = results[0]
        if format == "json":
            _write(output, res.model_dump_json(indent=2) + "\n")
        else:
            body, _ = render(build_report(res), format, spec_uri=f"{(spec or fx.spec_path(variants[0]))}".replace("\\", "/"))
            _write(output, body)
    else:
        base = output or Path("results")
        for res in results:
            p = base.parent / f"{base.stem}-{res.info.variant}{base.suffix or '.json'}" if output else Path("results") / f"test-run-{res.info.variant}.json"
            if format == "json":
                _write(p, res.model_dump_json(indent=2) + "\n")
            else:
                body, _ = render(build_report(res), format)
                _write(p.with_suffix("." + format), body)
            err.print(f"wrote {p}")
    raise typer.Exit(worst)


# ------------------------------------------------------------------------------------------------ scan
@app.command("scan")
@_guard
def scan_cmd(
    connection_env: Annotated[str, typer.Option("--connection-env", help="Environment variable that holds the connection string (never passed on the command line)")],
    mode: Annotated[str, typer.Option("--mode", help="catalog (read-only metadata audit)")] = "catalog",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    spec: Annotated[Path | None, typer.Option("--spec", help="Optional expected-policy manifest used to interpret catalog findings")] = None,
    schemas: Annotated[list[str] | None, typer.Option("--schema", help="Limit to these schemas")] = None,
    allow_privileged_account: Annotated[bool, typer.Option("--allow-privileged-account", help="Permit a superuser inspector (NOT recommended)")] = False,
    allow_target: Annotated[list[str] | None, typer.Option("--allow-target", help="Host/CIDR to add to the allowlist for this run (default: loopback only)")] = None,
    fail_on_static: Annotated[str, typer.Option("--fail-on-static", help="Exit 1 when a static risk at/above this severity exists (none by default)")] = "none",
    format: Annotated[str, typer.Option("--format", help="json | sarif | html | md")] = "json",
) -> None:
    """Read-only catalog audit of an authorized live database. [bold]No DDL, no DML, no row data.[/bold]"""
    from ..reporting.builder import build_report
    from ..reporting.exporters import render
    from ..rules.engine import evaluate
    from ..service import scan_source

    if mode != "catalog":
        _die("Only --mode catalog is available against a live source. Behavioural tests run in a disposable lab (see 'rls-sentinel test').")
    dsn = os.environ.get(connection_env)
    if not dsn:
        _die(f"Environment variable {connection_env} is not set.")
    s = load_settings()
    if allow_target:
        s.allowed_targets = [*s.allowed_targets, *allow_target]
    err.print("[bold yellow]READ-ONLY SOURCE[/bold yellow] · only bounded pg_catalog queries run · no DDL/DML · no row data collected")
    snap = scan_source(dsn, s, alias=connection_env, schemas=schemas, allow_privileged=allow_privileged_account)
    sp = load_spec(spec) if spec else None
    findings = evaluate(snap, sp, None)
    from ..harness.results import CoverageSummary, RunInfo

    info = RunInfo(run_id=secrets.token_hex(6), project=snap.source.alias, environment_mode="READ-ONLY SOURCE", postgres_version=snap.postgres_version,
                   schema_hash=snap.schema_hash, tool_version=__version__, ruleset_version=RULESET_VERSION, status="completed")
    res = RunResult(info=info, coverage=CoverageSummary(), findings=[f.model_dump(mode="json") for f in findings], snapshot=snap.model_dump(mode="json"))
    cov = snap.coverage
    console.print(Panel(f"PostgreSQL {cov.postgres_version} · schemas {cov.schemas_seen} · tables {cov.tables_seen} · policies {cov.policies_seen} · roles {cov.roles_seen}\n"
                        f"row data collected: {cov.source_row_data_collected} · runtime tests executed: {cov.runtime_tests_executed}\n"
                        f"skipped catalog objects: {len(cov.catalog_objects_skipped)}\n" + "\n".join(f"• {n}" for n in cov.coverage_notes),
                        title="Coverage manifest", border_style="cyan"))
    _print_findings([f.model_dump(mode="json") for f in findings])
    if format == "json":
        _write(output, res.model_dump_json(indent=2) + "\n")
    else:
        body, _ = render(build_report(res), format)
        _write(output, body)
    thr = _threshold(fail_on_static)
    if thr is not None and any(SEVERITY_ORDER[f.severity] <= thr and f.evidence_class != "INCONCLUSIVE" for f in findings):
        raise typer.Exit(EXIT_VIOLATION)
    raise typer.Exit(EXIT_OK)


# ------------------------------------------------------------------------------------------------ report
@app.command("report")
@_guard
def report_cmd(
    run_file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="Run file produced by 'test' or 'scan' (--format json)")],
    format: Annotated[str, typer.Option("--format", help="json | md | html | sarif | csv")] = "html",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    spec_uri: Annotated[str | None, typer.Option("--spec-uri", help="Repo-relative path used as fallback SARIF location")] = None,
    full: Annotated[bool, typer.Option("--full", help="Embed the catalog snapshot and spec in the JSON report")] = False,
) -> None:
    """Generate a reviewable report. No live schema edits are ever made."""
    from ..reporting.builder import build_report
    from ..reporting.exporters import render

    res = _load_run(run_file)
    body, _ = render(build_report(res, include_snapshot=full, spec_path=spec_uri), format, spec_uri=spec_uri)
    _write(output, body)
    if output:
        err.print(f"wrote {output} ({format})")


# ------------------------------------------------------------------------------------------------ diff
@app.command("diff")
@_guard
def diff_cmd(
    before: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    after: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    format: Annotated[str, typer.Option("--format", help="text | json")] = "text",
    fail_on_regression: Annotated[bool, typer.Option("--fail-on-regression", help="Exit 1 on test regressions")] = False,
) -> None:
    """Compare two snapshots / runs: policy drift and test-outcome differences."""
    from ..catalog.models import Snapshot
    from ..diff.snapshot_diff import compare_findings, diff_snapshots

    def load(p: Path) -> tuple[Snapshot, RunResult | None]:
        data = json.loads(p.read_text(encoding="utf-8"))
        if str(data.get("format", "")).startswith("rls-sentinel-run"):
            r = RunResult.model_validate(data)
            if not r.snapshot:
                raise SpecError(f"{p} has no catalog snapshot.")
            return Snapshot.model_validate(r.snapshot), r
        return Snapshot.model_validate(data), None

    (a, ra), (b, rb) = load(before), load(after)
    d = diff_snapshots(a, b, ra, rb)
    labels = compare_findings([Finding.model_validate(f) for f in (ra.findings if ra else [])], [Finding.model_validate(f) for f in (rb.findings if rb else [])],
                              after_has_runtime=bool(rb and rb.cases))
    if format == "json":
        console.print_json(json.dumps({"diff": d.model_dump(mode="json"), "finding_labels": {k: len(v) for k, v in labels.items()}}))
    else:
        console.print(f"[bold]schema[/bold] {d.from_hash[:19]}… → {d.to_hash[:19]}…   changes: {d.summary['changes']}  higher-risk: {d.summary['risk_higher']}  "
                      f"lower-risk: {d.summary['risk_lower']}  regressions: {d.summary['regressions']}  resolved: {d.summary['resolved']}")
        if d.identical:
            console.print("[green]No differences.[/green]")
        t = Table(header_style="bold")
        for c in ("Risk", "Category", "Change"):
            t.add_column(c, overflow="fold")
        for ch in d.changes:
            col = {"higher": "red", "lower": "green"}.get(ch.risk, "white")
            t.add_row(f"[{col}]{ch.risk}[/]", ch.category, ch.summary + (" [dim](text only)[/dim]" if ch.textual_only else ""))
        if d.changes:
            console.print(t)
        for b2 in d.behavioral:
            if b2.transition in ("regression", "resolved", "became_inconclusive"):
                console.print(f"  {b2.transition:>20}: {b2.case_id} ({b2.before} → {b2.after})")
        console.print("[dim]" + " ".join(d.caveats) + "[/dim]")
        console.print("findings: " + ", ".join(f"{k}={len(v)}" for k, v in labels.items()))
    raise typer.Exit(EXIT_VIOLATION if (fail_on_regression and d.summary["regressions"]) else EXIT_OK)


# ------------------------------------------------------------------------------------------------ whatif
@app.command("whatif")
@_guard
def whatif_cmd(
    fixture: Annotated[str, typer.Option("--fixture")],
    draft: Annotated[Path, typer.Option("--draft", exists=True, dir_okay=False, help="SQL file with the proposed policy change")],
    variant: Annotated[str, typer.Option("--variant")] = "vulnerable",
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    backend: Annotated[str | None, typer.Option("--backend")] = None,
) -> None:
    """Replay a draft policy change in a [bold]disposable clone[/bold] and diff the authorization matrix. Nothing is applied anywhere else."""
    from ..harness.servers import start_server
    from ..service import run_fixture_test
    from ..whatif.lab import BANNER, run_whatif

    s = load_settings()
    fx = find_fixture(fixture, s.fixtures_dir)
    server = start_server(s, backend=backend)
    try:
        base, _ = run_fixture_test(s, fx, variant, server=server)
        res = run_whatif(s, fx, variant, draft.read_text(encoding="utf-8"), baseline=base, server=server)
    finally:
        server.stop()
    console.print(Panel(BANNER, border_style="yellow"))
    if res.apply_error:
        console.print(f"[red]draft failed in the sandbox:[/red] {res.apply_error}")
        raise typer.Exit(EXIT_USAGE)
    console.print(f"baseline  : {base.coverage.passed} pass / {base.coverage.failed} fail / {base.coverage.inconclusive} inconclusive")
    console.print(f"sandbox   : {res.sandbox_coverage.passed} pass / {res.sandbox_coverage.failed} fail / {res.sandbox_coverage.inconclusive} inconclusive")
    console.print(f"verdict   : [bold]{res.verdict}[/bold] - {res.verdict_text}")
    for d in res.deltas:
        if d.kind in ("resolved", "regression", "broader_access"):
            console.print(f"  {d.kind:>14}: {d.case_id} ({d.before} → {d.after}) {d.detail}")
    if output:
        _write(output, res.model_dump_json(indent=2) + "\n")
    raise typer.Exit(EXIT_VIOLATION if res.verdict in ("regresses", "mixed") else EXIT_OK)


@app.command("export-tests")
@_guard
def export_tests(
    run_file: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    output: Annotated[Path, typer.Option("--output", "-o")] = Path("test_rls_authorization.py"),
    mode: Annotated[str, typer.Option("--mode", help="spec (all must PASS) | pin (lock current statuses)")] = "spec",
) -> None:
    """Export a runnable pytest regression suite from a run."""
    from ..reporting.pytest_export import generate_pytest

    res = _load_run(run_file)
    fixture_name = res.info.fixture
    if not res.spec or not fixture_name:
        _die("This run has no embedded spec/fixture; only fixture-based test runs can be exported.")
    _write(output, generate_pytest(Spec.model_validate(res.spec), fixture=fixture_name, variant=res.info.variant or "vulnerable", run=res, mode=mode))
    console.print(f"wrote {output}")


# ------------------------------------------------------------------------------------------------ serve + demo
def _make_settings(host: str, port: int, token: str | None) -> Settings:
    s = load_settings()
    s.host, s.port = host, port
    if token:
        s.api_token = token
    return s


@app.command("serve")
@_guard
def serve(
    host: Annotated[str, typer.Option("--host", envvar="SENTINEL_HOST")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", envvar="SENTINEL_PORT")] = 8787,
    generate_token: Annotated[bool, typer.Option("--generate-token", help="Require a random API token and print it once")] = False,
    open_browser: Annotated[bool, typer.Option("--open/--no-open")] = False,
) -> None:
    """Start the API and web UI. Binds to loopback by default; a non-loopback bind requires SENTINEL_API_TOKEN."""
    import uvicorn

    from ..api.app import create_app

    token = os.environ.get("SENTINEL_API_TOKEN") or (secrets.token_urlsafe(24) if generate_token else None)
    s = _make_settings(host, port, token)
    if not s.is_loopback_bind and not s.api_token:
        _die("Refusing to bind to a non-loopback address without SENTINEL_API_TOKEN (or --generate-token).")
    application = create_app(s)
    url = f"http://{'localhost' if s.is_loopback_bind else host}:{port}"
    console.print(Panel(f"[bold]RLS / SENTINEL[/bold]   {url}\nmode: {'token auth' if s.api_token else 'localhost single-user'} · "
                        f"UI: {'bundled' if s.ui_dir else 'not built (run npm run build in frontend/)'}\n"
                        f"lab: {application.state.ctx.servers.availability()['detail']}"
                        + (f"\n\n[bold yellow]API token (shown once):[/bold yellow] {token}" if generate_token and token else ""),
                        title="DATABASE ACCESS. VERIFIED.", border_style="green"))
    if open_browser and s.is_loopback_bind:
        webbrowser.open(url)
    uvicorn.run(application, host=host, port=port, log_level="warning", access_log=False)


@demo_app.command("up")
@_guard
def demo_up(port: Annotated[int, typer.Option("--port")] = 8787, open_browser: Annotated[bool, typer.Option("--open/--no-open")] = True) -> None:
    """Start the app locally with the bundled synthetic fixtures. No external credentials are needed."""
    import uvicorn

    from ..api.app import create_app

    s = _make_settings("127.0.0.1", port, None)
    if not s.fixtures_dir:
        _die("Bundled fixtures were not found.")
    application = create_app(s)
    avail = application.state.ctx.servers.availability()
    if not avail["available"]:
        _die(str(avail["detail"]), EXIT_ERROR)
    url = f"http://localhost:{port}"
    console.print(Panel(f"{url}\nlab backend: {avail['backend']} · {avail['detail']}\n\nDemo data is synthetic and tagged DEMO in the UI.\n"
                        "1) Open Overview → choose a fixture  2) Run tests  3) Review findings  4) Try the What-if Lab  5) Export a report",
                        title="RLS Sentinel demo", border_style="green"))
    if not s.ui_dir:
        console.print("[yellow]The web UI is not built; the API is available at /api/docs. Build it with: cd frontend && npm ci && npm run build[/yellow]")
    if open_browser:
        webbrowser.open(url)
    uvicorn.run(application, host="127.0.0.1", port=port, log_level="warning", access_log=False)


@demo_app.command("smoke")
@_guard
def demo_smoke() -> None:
    """Headless end-to-end check: run every bundled fixture (both variants) and compare with the documented outcomes."""
    from ..harness.servers import start_server
    from ..service import run_fixture_test

    s = load_settings()
    server = start_server(s)
    bad = 0
    t = Table(title=f"Demo smoke · PostgreSQL {server.version} ({server.kind})", header_style="bold")
    for c in ("Fixture", "Variant", "Cases", "Pass", "Fail", "Inconclusive", "Matches documented outcome", "Time"):
        t.add_column(c)
    try:
        for fx in discover_fixtures(s.fixtures_dir):
            for v in fx.variants:
                res, _ = run_fixture_test(s, fx, v, server=server)
                want = fx.expected.get(v, {})
                got_fail = sorted(c.case_id for c in res.cases if c.status == "FAIL")
                got_inc = sorted(c.case_id for c in res.cases if c.status == "INCONCLUSIVE")
                match = got_fail == sorted(want.get("fail", [])) and got_inc == sorted(want.get("inconclusive", []))
                bad += 0 if match else 1
                t.add_row(fx.name, v, str(res.coverage.expected_assertions), str(res.coverage.passed), str(res.coverage.failed),
                          str(res.coverage.inconclusive), "[green]yes[/green]" if match else "[red]NO[/red]", f"{res.info.duration_s}s")
    finally:
        server.stop()
    console.print(t)
    raise typer.Exit(EXIT_OK if bad == 0 else EXIT_ERROR)


def main() -> None:  # pragma: no cover
    app()


_ = (load_spec_text,)

if __name__ == "__main__":  # pragma: no cover
    main()
