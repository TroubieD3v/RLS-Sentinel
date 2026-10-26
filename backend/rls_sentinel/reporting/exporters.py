"""Report exporters: JSON, Markdown, self-contained HTML, SARIF 2.1.0 and CSV (formula-injection safe)."""

from __future__ import annotations

import csv
import html
import io
import json
import os
from pathlib import Path
from typing import Any

import jsonschema

from .. import RULESET_VERSION, TOOL_NAME, __version__
from ..rules.registry import RULES

SARIF_SCHEMA_PATH = Path(__file__).parent / "schemas" / "sarif-schema-2.1.0.json"
SARIF_SCHEMA_URI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
# Optional project URL for SARIF consumers. Deliberately not hard-coded: set SENTINEL_INFORMATION_URI to your repository URL.
INFO_URI = os.environ.get("SENTINEL_INFORMATION_URI") or None

# ------------------------------------------------------------------------------------------------ JSON
def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


# ------------------------------------------------------------------------------------------- Markdown
def _md(s: Any) -> str:
    t = str(s if s is not None else "")
    t = t.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`").replace("<", "&lt;").replace(">", "&gt;")
    return " ".join(t.split())


def to_markdown(report: dict[str, Any]) -> str:
    sc, run, cov, summ = report["scope"], report["run"], report["coverage"], report["summary"]
    out: list[str] = []
    w = out.append
    w(f"# RLS Sentinel report — {_md(run['project'])}\n")
    w("> **PERMISSIONS ARE NOT PROOF. TEST THEM.** Results below describe a tested schema in a disposable database; see Limitations.\n")
    w(f"- **Environment:** {_md(sc['environment'])} · PostgreSQL {_md(sc['postgres_version'])} ({_md(sc['server'])})")
    w(f"- **Fixture:** {_md(sc['fixture'])} / {_md(sc['variant'])} · **Identity:** {_md(sc['identity_adapter_note'])}")
    w(f"- **Run:** `{_md(run['run_id'])}` · tool {report['tool']['version']} · ruleset {report['tool']['ruleset']}")
    r = report["reproducibility"]
    w(f"- **Reproducibility:** schema `{_md(r['schema_hash'])}` · spec `{_md(r['spec_checksum'])}` · fixture `{_md(r['fixture_fingerprint'])}`\n")
    w("## Coverage\n")
    w("```text\n" + cov["panel"] + "\n```\n")
    w(f"Rows read from the database: none retained (`row_contents_retained: {str(sc['row_contents_retained']).lower()}`).\n")
    w("## Summary\n")
    w("| Evidence class | Count |\n|---|---|")
    for k, v in sorted(summ["by_evidence_class"].items()):
        w(f"| {_md(k)} | {v} |")
    w("")
    w("| Severity | Count |\n|---|---|")
    for k, v in sorted(summ["by_severity"].items()):
        w(f"| {_md(k)} | {v} |")
    w("")
    w("## Findings\n")
    if not report["findings"]:
        w("_No findings._\n")
    for f in report["findings"]:
        w(f"### {_md(f['rule_id'])} · {_md(f['title'])}\n")
        w(f"- **Severity:** {_md(f['severity'])} — {_md(f['severity_rationale'])}")
        w(f"- **Evidence class:** {_md(f['evidence_class'])} · **provenance:** {_md(', '.join(f['provenance']))} · **confidence:** {_md(f['confidence'])}")
        w(f"- **Subject:** `{_md(f['subject'])}`")
        w(f"- **What happened:** {_md(f['summary'])}")
        if f.get("why_it_matters"):
            w(f"- **Why it matters:** {_md(f['why_it_matters'])}")
        if f.get("expected") or f.get("observed"):
            w(f"- **Expected / observed:** {_md(f.get('expected'))} / {_md(f.get('observed'))}")
        if f.get("case_ids"):
            w(f"- **Cases:** {_md(', '.join(f['case_ids'][:10]))}")
        for ev in f.get("evidence", [])[:4]:
            w(f"  - evidence [{_md(ev['kind'])}] {_md(ev['summary'])}")
        if f.get("reproduction"):
            w("- **Reproduce (disposable fixture):**\n\n```text\n" + "\n".join(f["reproduction"]).replace("```", "'''") + "\n```")
        if f.get("remediation"):
            w(f"- **Remediation (review before applying):** {_md(f['remediation'])}")
        if f.get("limitations"):
            w(f"- **Limitations:** {_md(f['limitations'])}")
        refs = " · ".join(f"<{u}>" for u in f.get("references", []))
        if refs:
            w(f"- **References:** {refs}")
        w("")
    w("## Test cases\n")
    w("| Case | Actor | Operation | Expected | Observed | Gate | Status |\n|---|---|---|---|---|---|---|")
    for c in report["cases"]:
        w(f"| {_md(c['case_id'])} | {_md(c['actor'])} | {_md(c['operation'])} | {_md(c['expected'])} | {_md(c['observed'])} | {_md(c['gate'])} | **{_md(c['status'])}** |")
    w("\n## Limitations\n")
    for lim in report["limitations"]:
        w(f"- {_md(lim)}")
    return "\n".join(out) + "\n"


# ----------------------------------------------------------------------------------------------- HTML
_STATE_CLASS = {"ALLOW_VERIFIED": "ok", "DENY_VERIFIED": "ok2", "FAIL": "bad", "UNKNOWN": "unk", "EXPECTED_ALLOW": "exp", "EXPECTED_DENY": "exp"}
_STATE_GLYPH = {"ALLOW_VERIFIED": "✓ ALLOW", "DENY_VERIFIED": "⊘ DENY", "FAIL": "✕ FAIL", "UNKNOWN": "? UNKNOWN", "EXPECTED_ALLOW": "○ allow", "EXPECTED_DENY": "○ deny"}

_CSS = """
:root{--bg:#080d15;--surface:#0f1826;--raised:#142033;--border:#29374c;--text:#e8eef7;--muted:#9baac0;--teal:#43ddc6;--violet:#af9bff;--amber:#f4be61;--coral:#fb7288;--blue:#7ab6ff}
@media (prefers-color-scheme:light){:root{--bg:#f6f8fc;--surface:#fff;--raised:#f0f4fa;--border:#d9e1ed;--text:#182437;--muted:#4f6076;--teal:#0b6b5e;--violet:#5a3fd0;--amber:#8a5a00;--coral:#b3203a;--blue:#1d5fb4}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 Inter,Geist,system-ui,sans-serif}
main{max-width:1180px;margin:0 auto;padding:32px 20px 64px}h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:32px 0 12px;border-bottom:1px solid var(--border);padding-bottom:6px}
code,pre,.mono{font-family:'JetBrains Mono',ui-monospace,Consolas,monospace;font-size:12.5px}.muted{color:var(--muted)}
.brand{display:flex;align-items:center;gap:10px;letter-spacing:.14em;font-weight:700;font-size:13px}.tag{color:var(--muted);letter-spacing:.12em;font-size:11px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px;margin:12px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}.stat b{display:block;font-size:26px}
pre{background:var(--raised);border:1px solid var(--border);border-radius:8px;padding:12px;overflow:auto;white-space:pre-wrap}
table{border-collapse:collapse;width:100%}th,td{border:1px solid var(--border);padding:6px 8px;text-align:left;vertical-align:top}th{background:var(--raised)}
.lozenge{display:inline-block;border-radius:999px;padding:1px 9px;font-size:11px;font-weight:700;border:1px solid currentColor;letter-spacing:.04em}
.CONFIRMED_VIOLATION{color:var(--coral)}.CONFIGURATION_RISK{color:var(--amber)}.INCONCLUSIVE{color:var(--blue)}.ok{color:var(--teal)}.ok2{color:var(--violet)}.bad{color:var(--coral);font-weight:700}.unk{color:var(--amber)}.exp{color:var(--muted)}
.banner{border:1px solid var(--amber);border-radius:8px;padding:8px 12px;color:var(--amber);margin:12px 0;font-weight:600}
@media print{body{background:#fff;color:#000}}
"""

_LOGO = ('<svg width="28" height="28" viewBox="0 0 32 32" role="img" aria-label="RLS Sentinel mark" xmlns="http://www.w3.org/2000/svg">'
         '<ellipse cx="16" cy="7" rx="10" ry="4" fill="none" stroke="currentColor" stroke-width="2"/>'
         '<path d="M6 7v18c0 2.2 4.5 4 10 4s10-1.8 10-4V7" fill="none" stroke="currentColor" stroke-width="2"/>'
         '<circle cx="16" cy="17" r="4.2" fill="none" stroke="#43ddc6" stroke-width="2"/><circle cx="16" cy="17" r="1.6" fill="#43ddc6"/></svg>')


def _e(x: Any) -> str:
    return html.escape(str(x if x is not None else ""), quote=True)


def to_html(report: dict[str, Any]) -> str:
    sc, run, cov = report["scope"], report["run"], report["coverage"]
    p: list[str] = []
    w = p.append
    w("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    w("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">")
    w(f"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>RLS Sentinel report — {_e(run['project'])}</title><style>{_CSS}</style></head><body><main>")
    w(f"<div class=\"brand\">{_LOGO} RLS / SENTINEL</div><div class=\"tag\">DATABASE ACCESS. VERIFIED. · PERMISSIONS ARE NOT PROOF. TEST THEM.</div>")
    w(f"<h1>{_e(run['project'])}</h1>")
    w(f"<p class=\"muted\">Run <span class=\"mono\">{_e(run['run_id'])}</span> · {_e(sc['environment'])} · PostgreSQL {_e(sc['postgres_version'])} ({_e(sc['server'])}) · "
      f"fixture {_e(sc['fixture'])}/{_e(sc['variant'])} · tool {_e(report['tool']['version'])}</p>")
    w(f"<div class=\"banner\">{_e(sc['identity_adapter_note'])}</div>")
    w("<div class=\"grid\">")
    for label, val, cls in (("Expected assertions", cov["expected_assertions"], ""), ("PASS", cov["passed"], "ok"), ("FAIL", cov["failed"], "bad"),
                            ("INCONCLUSIVE", cov["inconclusive"], "unk"), ("Not executed", cov["not_executed"], "exp"),
                            ("Verified coverage", f"{cov['verified_coverage_pct']}%", "")):
        w(f"<div class=\"card stat\"><span class=\"muted\">{_e(label)}</span><b class=\"{cls}\">{_e(val)}</b></div>")
    w("</div>")
    w(f"<h2>Authorization coverage</h2><pre>{_e(cov['panel'])}</pre>")
    w("<h2>Findings</h2>")
    if not report["findings"]:
        w("<p class=\"muted\">No findings.</p>")
    for f in report["findings"]:
        w("<div class=\"card\">")
        w(f"<div><span class=\"lozenge {_e(f['evidence_class'])}\">{_e(f['evidence_class'].replace('_', ' '))}</span> "
          f"<strong>{_e(f['rule_id'])} · {_e(f['title'])}</strong> <span class=\"muted\">· {_e(f['severity'])}</span></div>")
        w(f"<p>{_e(f['summary'])}</p>")
        w(f"<p class=\"muted\">Severity rationale: {_e(f['severity_rationale'])}<br>Provenance: {_e(', '.join(f['provenance']))} · Confidence: {_e(f['confidence'])} · Subject: <span class=\"mono\">{_e(f['subject'])}</span></p>")
        if f.get("why_it_matters"):
            w(f"<p><b>Why it matters.</b> {_e(f['why_it_matters'])}</p>")
        if f.get("expected") or f.get("observed"):
            w(f"<p><b>Expected</b> <span class=\"mono\">{_e(f.get('expected'))}</span> · <b>Observed</b> <span class=\"mono\">{_e(f.get('observed'))}</span></p>")
        if f.get("reproduction"):
            w(f"<pre>{_e(chr(10).join(f['reproduction']))}</pre>")
        if f.get("remediation"):
            w(f"<p><b>Remediation (review first).</b> {_e(f['remediation'])}</p>")
        if f.get("limitations"):
            w(f"<p class=\"muted\"><b>Limitations.</b> {_e(f['limitations'])}</p>")
        w("</div>")
    mx = report["matrix"]
    w("<h2>Authorization matrix (executed cases only)</h2>")
    if mx["rows"]:
        w("<div style=\"overflow:auto\"><table><thead><tr><th>Actor</th>")
        for c in mx["columns"]:
            w(f"<th class=\"mono\">{_e(c['key'])}</th>")
        w("</tr></thead><tbody>")
        for r in mx["rows"]:
            w(f"<tr><th>{_e(r['actor'])}<br><span class=\"muted mono\">{_e(r['db_role'])}</span></th>")
            for c in mx["columns"]:
                cells = r["cells"].get(c["key"], [])
                if not cells:
                    w("<td class=\"muted\">·</td>")
                    continue
                w("<td>" + "<br>".join(f"<span class=\"{_STATE_CLASS.get(x['state'], '')}\" title=\"{_e(x['case_id'])}\">{_e(_STATE_GLYPH.get(x['state'], x['state']))}</span>" for x in cells) + "</td>")
            w("</tr>")
        w("</tbody></table></div>")
    w("<h2>Cases</h2><div style=\"overflow:auto\"><table><thead><tr><th>Case</th><th>Actor</th><th>Operation</th><th>Expected</th><th>Observed</th><th>Gate</th><th>Status</th></tr></thead><tbody>")
    for c in report["cases"]:
        w(f"<tr><td class=\"mono\">{_e(c['case_id'])}</td><td>{_e(c['actor'])}</td><td>{_e(c['operation'])}</td><td>{_e(c['expected'])}</td><td>{_e(c['observed'])}</td><td>{_e(c['gate'])}</td><td><b>{_e(c['status'])}</b></td></tr>")
    w("</tbody></table></div>")
    w("<h2>Limitations</h2><ul>" + "".join(f"<li>{_e(x)}</li>" for x in report["limitations"]) + "</ul>")
    w(f"<p class=\"muted mono\">schema {_e(report['reproducibility']['schema_hash'])} · spec {_e(report['reproducibility']['spec_checksum'])}</p>")
    w("</main></body></html>")
    return "".join(p)


# ----------------------------------------------------------------------------------------------- CSV
def _csv_cell(v: Any) -> str:
    s = "" if v is None else str(v)
    if s[:1] in ("=", "+", "-", "@", "\t", "\r"):
        s = "'" + s  # neutralize spreadsheet formula injection
    return s


def to_csv(report: dict[str, Any]) -> str:
    buf = io.StringIO()
    wr = csv.writer(buf, quoting=csv.QUOTE_ALL)
    wr.writerow(["rule_id", "severity", "evidence_class", "subject", "summary", "provenance", "confidence", "case_ids", "remediation"])
    for f in report["findings"]:
        wr.writerow([_csv_cell(x) for x in (f["rule_id"], f["severity"], f["evidence_class"], f["subject"], f["summary"],
                                            ";".join(f["provenance"]), f["confidence"], ";".join(f["case_ids"]), f["remediation"])])
    return buf.getvalue()


# ----------------------------------------------------------------------------------------------- SARIF
_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Informational": "note", "Needs triage": "note"}


def _sarif_level(f: dict[str, Any]) -> str:
    if f["evidence_class"] == "INCONCLUSIVE":
        return "note"
    lvl = _LEVEL.get(f["severity"], "note")
    if f["evidence_class"] == "CONFIGURATION_RISK" and lvl == "error":
        lvl = "warning"  # static risks are never reported at error level
    return lvl


def to_sarif(report: dict[str, Any], *, spec_uri: str | None = None) -> dict[str, Any]:
    used = sorted({f["rule_id"] for f in report["findings"]})
    rules: list[Any] = []
    index: dict[str, Any] = {}
    for rid in used:
        m = RULES.get(rid)
        if m is None:
            continue
        index[rid] = len(rules)
        rules.append({
            "id": rid, "name": m.title.title().replace(" ", "").replace("/", "").replace("-", ""),
            "shortDescription": {"text": m.title}, "fullDescription": {"text": m.description},
            "help": {"text": f"{m.remediation}\nMinimum evidence: {m.min_evidence}", "markdown": f"**Remediation:** {m.remediation}\n\n**Minimum evidence:** {m.min_evidence}"},
            "defaultConfiguration": {"level": m.default_level},
            "properties": {"tags": ["security", "postgresql", "row-level-security", m.category], "precision": "high" if m.supports_runtime else "medium"},
        })
        if m.references or INFO_URI:
            rules[-1]["helpUri"] = m.references[0] if m.references else INFO_URI
    results = []
    for f in report["findings"]:
        if f["rule_id"] not in index:
            continue
        loc: list[dict[str, Any]] = []
        fl = f.get("location")
        if fl and fl.get("path"):
            region = {"startLine": int(fl["line"])} if fl.get("line") else None
            pl: dict[str, Any] = {"artifactLocation": {"uri": str(fl["path"]).replace("\\", "/"), "uriBaseId": "%SRCROOT%"}}
            if region:
                pl["region"] = region
            loc.append({"physicalLocation": pl, "logicalLocations": [{"fullyQualifiedName": f["subject"], "kind": "member"}]})
        elif spec_uri:
            loc.append({"physicalLocation": {"artifactLocation": {"uri": spec_uri, "uriBaseId": "%SRCROOT%"}, "region": {"startLine": 1}},
                        "logicalLocations": [{"fullyQualifiedName": f["subject"], "kind": "member"}]})
        else:
            loc.append({"logicalLocations": [{"fullyQualifiedName": f["subject"], "kind": "member"}]})
        results.append({
            "ruleId": f["rule_id"], "ruleIndex": index[f["rule_id"]], "level": _sarif_level(f),
            "kind": "review" if f["evidence_class"] == "INCONCLUSIVE" else "fail",
            "message": {"text": f"{f['summary']} [{f['evidence_class']}; {', '.join(f['provenance'])}]"},
            "locations": loc,
            "partialFingerprints": {"rlsSentinel/v1": f["fingerprint"]},
            "properties": {"severity": f["severity"], "evidenceClass": f["evidence_class"], "confidence": f["confidence"],
                           "caseIds": f["case_ids"], "verifiedBy": f["verified_by"]},
        })
    return {
        "$schema": SARIF_SCHEMA_URI, "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "version": __version__, "semanticVersion": __version__, **({"informationUri": INFO_URI} if INFO_URI else {}),
                                "rules": rules, "properties": {"ruleset": RULESET_VERSION}}},
            "results": results,
            "invocations": [{"executionSuccessful": report["run"]["status"] == "completed",
                             "properties": {"coverage": report["coverage"]["verified_coverage_pct"], "postgres": report["scope"]["postgres_version"]}}],
            "automationDetails": {"id": f"rls-sentinel/{report['run']['run_id']}"},
            "properties": {"environment": report["scope"]["environment"], "sourceRowDataCollected": False},
        }],
    }


def validate_sarif(doc: dict[str, Any]) -> list[str]:
    """Validate against the vendored official SARIF 2.1.0 JSON schema. Returns a list of error strings."""
    schema = json.loads(SARIF_SCHEMA_PATH.read_text(encoding="utf-8"))
    v = jsonschema.Draft4Validator(schema)
    return [f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message[:200]}" for e in sorted(v.iter_errors(doc), key=lambda e: list(e.absolute_path))]


# ------------------------------------------------------------------------------------- dispatcher
FORMATS = {"json": "application/json", "md": "text/markdown", "markdown": "text/markdown", "html": "text/html",
           "sarif": "application/sarif+json", "csv": "text/csv"}


def render(report: dict[str, Any], fmt: str, *, spec_uri: str | None = None) -> tuple[str, str]:
    fmt = fmt.lower()
    if fmt == "json":
        return to_json(report), FORMATS["json"]
    if fmt in ("md", "markdown"):
        return to_markdown(report), FORMATS["md"]
    if fmt == "html":
        return to_html(report), FORMATS["html"]
    if fmt == "csv":
        return to_csv(report), FORMATS["csv"]
    if fmt == "sarif":
        doc = to_sarif(report, spec_uri=spec_uri)
        errors = validate_sarif(doc)
        if errors:
            raise ValueError("Generated SARIF failed schema validation: " + "; ".join(errors[:3]))
        return json.dumps(doc, indent=2, ensure_ascii=False) + "\n", FORMATS["sarif"]
    raise ValueError(f"Unknown report format '{fmt}'. Choose one of: json, md, html, sarif, csv.")
