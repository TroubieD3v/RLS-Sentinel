"""Snapshot / policy drift analysis and finding lifecycle labels.

A textual or structural difference is *one signal*. The diff never claims that a change is exploitable;
behavioural conclusions come only from test results that actually ran on both sides.
"""

from __future__ import annotations

from typing import Any, Literal

from pglast import parse_sql
from pglast.stream import RawStream
from pydantic import BaseModel, Field

from ..catalog.exprs import analyze_expression
from ..catalog.models import PolicyRec, Snapshot
from ..findings.models import EvidenceRef, Finding, make_fingerprint, make_id
from ..harness.results import CaseResult, RunResult

Risk = Literal["higher", "lower", "neutral", "unknown"]


class Change(BaseModel):
    category: str
    kind: Literal["added", "removed", "changed"]
    subject: str
    summary: str
    before: Any = None
    after: Any = None
    risk: Risk = "unknown"
    textual_only: bool = False
    note: str = ""


class CaseChange(BaseModel):
    case_id: str
    before: str | None
    after: str | None
    transition: Literal["regression", "resolved", "unchanged", "new_case", "removed_case", "became_inconclusive", "other"]
    summary: str


class SnapshotDiff(BaseModel):
    format: str = "rls-sentinel-diff/1"
    from_hash: str
    to_hash: str
    from_version: str = ""
    to_version: str = ""
    changes: list[Change] = Field(default_factory=list)
    behavioral: list[CaseChange] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)
    caveats: list[str] = Field(default_factory=list)

    @property
    def identical(self) -> bool:
        return not self.changes and not any(c.transition not in ("unchanged",) for c in self.behavioral)


def normalize_expr(expr: str | None) -> str | None:
    if expr is None:
        return None
    try:
        tree = parse_sql("SELECT " + expr)
        return str(RawStream()(tree[0].stmt.targetList[0].val))
    except Exception:
        return " ".join(expr.split())


def _pol_key(p: PolicyRec) -> str:
    return f"{p.table}:{p.name}"


def diff_snapshots(a: Snapshot, b: Snapshot, run_a: RunResult | None = None, run_b: RunResult | None = None) -> SnapshotDiff:
    ch: list[Change] = []
    add = ch.append

    ta = {t.qualified: t for t in a.tables}
    tb = {t.qualified: t for t in b.tables}
    for q in sorted(tb.keys() - ta.keys()):
        t = tb[q]
        pols = [p for p in b.policies if p.table == q]
        risk: Risk = "higher" if (t.kind in ("table", "partitioned_table") and (not t.rls_enabled or not pols)) else "neutral"
        add(Change(category="table", kind="added", subject=q, summary=f"New {t.kind} {q}" + (" without RLS" if not t.rls_enabled and t.kind in ("table", "partitioned_table") else ""),
                   after={"rls_enabled": t.rls_enabled, "policies": len(pols)}, risk=risk,
                   note="Newly uncovered table: no tests exist yet." if risk == "higher" else ""))
    for q in sorted(ta.keys() - tb.keys()):
        add(Change(category="table", kind="removed", subject=q, summary=f"Removed {ta[q].kind} {q}", risk="neutral"))
    for q in sorted(ta.keys() & tb.keys()):
        x, y = ta[q], tb[q]
        if x.rls_enabled != y.rls_enabled:
            add(Change(category="rls", kind="changed", subject=q, summary=f"RLS {'enabled' if y.rls_enabled else 'DISABLED'} on {q}",
                       before=x.rls_enabled, after=y.rls_enabled, risk="lower" if y.rls_enabled else "higher"))
        if x.rls_forced != y.rls_forced:
            add(Change(category="force", kind="changed", subject=q, summary=f"FORCE ROW LEVEL SECURITY {'enabled' if y.rls_forced else 'removed'} on {q}",
                       before=x.rls_forced, after=y.rls_forced, risk="lower" if y.rls_forced else "higher"))
        if x.owner != y.owner:
            add(Change(category="owner", kind="changed", subject=q, summary=f"Owner of {q}: {x.owner} → {y.owner}", before=x.owner, after=y.owner, risk="unknown"))
        if x.is_view and y.is_view and x.security_invoker != y.security_invoker:
            add(Change(category="view", kind="changed", subject=q, summary=f"View {q} security_invoker {x.security_invoker} → {y.security_invoker}",
                       before=x.security_invoker, after=y.security_invoker, risk="lower" if y.security_invoker else "higher"))
        if x.view_definition != y.view_definition and y.is_view:
            add(Change(category="view", kind="changed", subject=q, summary=f"View definition of {q} changed", risk="unknown",
                       note="Definition text differs; behavioural effect unknown without tests."))
    for q in sorted(tb.keys() - ta.keys()):
        t = tb[q]
        if t.is_view and not t.security_invoker:
            add(Change(category="view", kind="added", subject=q, summary=f"New owner-privileged view {q} (no security_invoker)", risk="higher"))

    pa = {_pol_key(p): p for p in a.policies}
    pb = {_pol_key(p): p for p in b.policies}
    for k in sorted(pb.keys() - pa.keys()):
        p = pb[k]
        u = analyze_expression(p.using_expr)
        broad = p.permissive and (u.is_const_true or analyze_expression(p.check_expr).is_const_true)
        add(Change(category="policy", kind="added", subject=k, summary=f"New {'permissive' if p.permissive else 'restrictive'} {p.command} policy {p.name} on {p.table}",
                   after=_pol_view(p), risk="higher" if broad else ("lower" if not p.permissive else "unknown"),
                   note="Constant-TRUE permissive policy." if broad else ""))
    for k in sorted(pa.keys() - pb.keys()):
        p = pa[k]
        add(Change(category="policy", kind="removed", subject=k, summary=f"Removed {'permissive' if p.permissive else 'restrictive'} {p.command} policy {p.name} on {p.table}",
                   before=_pol_view(p), risk="higher" if not p.permissive else "lower",
                   note="" if not p.permissive else "Removing a permissive policy narrows access; legitimate users may be blocked."))
    for k in sorted(pa.keys() & pb.keys()):
        px, py = pa[k], pb[k]
        diffs = []
        textual_only = False
        if px.command != py.command:
            diffs.append(f"command {px.command}→{py.command}")
        if px.permissive != py.permissive:
            diffs.append(f"{'permissive' if px.permissive else 'restrictive'}→{'permissive' if py.permissive else 'restrictive'}")
        if px.roles != py.roles:
            diffs.append(f"roles {px.roles}→{py.roles}")
        risk = "unknown"
        for fld, label in (("using_expr", "USING"), ("check_expr", "WITH CHECK")):
            vx, vy = getattr(px, fld), getattr(py, fld)
            if vx != vy:
                if normalize_expr(vx) == normalize_expr(vy):
                    textual_only = True
                    diffs.append(f"{label} text differs (identical after normalization)")
                else:
                    diffs.append(f"{label} changed")
                    ex, ey = analyze_expression(vx), analyze_expression(vy)
                    if ey.is_const_true and not ex.is_const_true:
                        risk = "higher"
                    elif ex.is_const_true and not ey.is_const_true:
                        risk = "lower"
        if px.permissive and not py.permissive:
            risk = "lower"
        elif not px.permissive and py.permissive:
            risk = "higher"
        if diffs:
            add(Change(category="policy", kind="changed", subject=k, summary=f"Policy {py.name} on {py.table}: " + "; ".join(diffs),
                       before=_pol_view(px), after=_pol_view(py), risk=risk,
                       textual_only=textual_only and len(diffs) == 1,
                       note="Only the text differs; normalized form is identical." if textual_only and len(diffs) == 1 else
                       "Direction is a heuristic on constant expressions; semantics unverified without a test run."))

    ra, rb = {r.name: r for r in a.roles}, {r.name: r for r in b.roles}
    for n in sorted(rb.keys() - ra.keys()):
        r = rb[n]
        add(Change(category="role", kind="added", subject=n, summary=f"New role {n}" + (" (BYPASSRLS)" if r.bypassrls else "") + (" (superuser)" if r.superuser else ""),
                   after={"login": r.login, "bypassrls": r.bypassrls}, risk="higher" if (r.bypassrls or r.superuser) else "neutral"))
    for n in sorted(ra.keys() - rb.keys()):
        add(Change(category="role", kind="removed", subject=n, summary=f"Removed role {n}", risk="neutral"))
    for n in sorted(ra.keys() & rb.keys()):
        rx, ry = ra[n], rb[n]
        for attr in ("superuser", "bypassrls", "login", "createrole", "inherit"):
            if getattr(rx, attr) != getattr(ry, attr):
                worse = attr in ("superuser", "bypassrls") and getattr(ry, attr)
                add(Change(category="role", kind="changed", subject=n, summary=f"Role {n}: {attr} {getattr(rx, attr)} → {getattr(ry, attr)}",
                           before=getattr(rx, attr), after=getattr(ry, attr), risk="higher" if worse else "unknown"))

    ma = {(m.role, m.member): m for m in a.memberships}
    mb = {(m.role, m.member): m for m in b.memberships}
    for mk in sorted(mb.keys() - ma.keys()):
        add(Change(category="membership", kind="added", subject=f"{mk[1]}→{mk[0]}", summary=f"{mk[1]} became a member of {mk[0]}", risk="unknown"))
    for mk in sorted(ma.keys() - mb.keys()):
        add(Change(category="membership", kind="removed", subject=f"{mk[1]}→{mk[0]}", summary=f"{mk[1]} left {mk[0]}", risk="unknown"))

    ga = {(g.object_type, g.object, g.grantee, g.privilege) for g in a.grants if g.object_type != "default"}
    gb = {(g.object_type, g.object, g.grantee, g.privilege) for g in b.grants if g.object_type != "default"}
    for gk in sorted(gb - ga):
        sev: Risk = "higher"
        add(Change(category="grant", kind="added", subject=f"{gk[2]}@{gk[1]}", summary=f"GRANT {gk[3]} on {gk[1]} to {gk[2]}", after=list(gk), risk=sev))
    for gk in sorted(ga - gb):
        add(Change(category="grant", kind="removed", subject=f"{gk[2]}@{gk[1]}", summary=f"REVOKE {gk[3]} on {gk[1]} from {gk[2]}", before=list(gk), risk="lower"))

    fa = {f.qualified: f for f in a.functions}
    fb = {f.qualified: f for f in b.functions}
    for q in sorted(fb.keys() - fa.keys()):
        f = fb[q]
        add(Change(category="function", kind="added", subject=q, summary=f"New {'SECURITY DEFINER ' if f.security_definer else ''}function {q}",
                   risk="higher" if f.security_definer else "neutral", note="Newly exposed definer function." if f.security_definer else ""))
    for q in sorted(fa.keys() & fb.keys()):
        fx, fy = fa[q], fb[q]
        if fx.security_definer != fy.security_definer:
            add(Change(category="function", kind="changed", subject=q, summary=f"{q}: SECURITY {'DEFINER' if fy.security_definer else 'INVOKER'}",
                       risk="higher" if fy.security_definer else "lower"))
        if fx.has_fixed_search_path != fy.has_fixed_search_path:
            add(Change(category="function", kind="changed", subject=q, summary=f"{q}: search_path {'pinned' if fy.has_fixed_search_path else 'no longer pinned'}",
                       risk="lower" if fy.has_fixed_search_path else "higher"))
        if fx.src_sha256 != fy.src_sha256:
            add(Change(category="function", kind="changed", subject=q, summary=f"Body of {q} changed", risk="unknown", note="Function bodies are compared by hash only."))

    sa, sb = {s.name for s in a.schemas}, {s.name for s in b.schemas}
    for n in sorted(sb - sa):
        add(Change(category="schema", kind="added", subject=n, summary=f"New schema {n}", risk="unknown"))
    for n in sorted(sa - sb):
        add(Change(category="schema", kind="removed", subject=n, summary=f"Removed schema {n}", risk="neutral"))

    behavioral = diff_runs(run_a, run_b) if (run_a and run_b) else []
    summary = {
        "changes": len(ch),
        "risk_higher": sum(1 for c in ch if c.risk == "higher"),
        "risk_lower": sum(1 for c in ch if c.risk == "lower"),
        "textual_only": sum(1 for c in ch if c.textual_only),
        "regressions": sum(1 for c in behavioral if c.transition == "regression"),
        "resolved": sum(1 for c in behavioral if c.transition == "resolved"),
    }
    caveats = ["Structural differences are signals, not proof: 'risk' is a heuristic direction, not an exploitability claim."]
    if not behavioral:
        caveats.append("No test results were supplied for both sides, so no behavioural conclusion is drawn.")
    return SnapshotDiff(from_hash=a.schema_hash, to_hash=b.schema_hash, from_version=a.postgres_version, to_version=b.postgres_version,
                        changes=ch, behavioral=behavioral, summary=summary, caveats=caveats)


def _pol_view(p: PolicyRec) -> dict[str, Any]:
    return {"command": p.command, "permissive": p.permissive, "roles": p.roles, "using": p.using_expr, "check": p.check_expr}


def diff_runs(a: RunResult, b: RunResult) -> list[CaseChange]:
    ca = {c.case_id: c for c in a.cases}
    cb = {c.case_id: c for c in b.cases}
    out: list[CaseChange] = []
    for cid in list(cb) + [k for k in ca if k not in cb]:
        x, y = ca.get(cid), cb.get(cid)
        if x is None:
            out.append(CaseChange(case_id=cid, before=None, after=y.status if y else None, transition="new_case", summary="case only in the new run"))
        elif y is None:
            out.append(CaseChange(case_id=cid, before=x.status, after=None, transition="removed_case", summary="case only in the old run"))
        elif x.status == y.status:
            out.append(CaseChange(case_id=cid, before=x.status, after=y.status, transition="unchanged", summary="same status"))
        elif y.status == "FAIL" and x.status != "FAIL":
            out.append(CaseChange(case_id=cid, before=x.status, after=y.status, transition="regression", summary=_why(y)))
        elif x.status == "FAIL" and y.status == "PASS":
            out.append(CaseChange(case_id=cid, before=x.status, after=y.status, transition="resolved", summary="previously failing case now passes"))
        elif y.status == "INCONCLUSIVE":
            out.append(CaseChange(case_id=cid, before=x.status, after=y.status, transition="became_inconclusive", summary=_why(y)))
        else:
            out.append(CaseChange(case_id=cid, before=x.status, after=y.status, transition="other", summary=f"{x.status} → {y.status}"))
    return out


def _why(c: CaseResult) -> str:
    return c.reason[:200]


# --------------------------------------------------------------------- finding lifecycle labels
def compare_findings(before: list[Finding], after: list[Finding], *, after_has_runtime: bool) -> dict[str, list[dict[str, Any]]]:
    """Label findings new / resolved / persisting / unverified by stable fingerprint."""
    fb = {f.fingerprint: f for f in before}
    fa = {f.fingerprint: f for f in after}
    out: dict[str, list[dict[str, Any]]] = {"new": [], "resolved": [], "persisting": [], "unverified": []}
    for fp, f in fa.items():
        item = {"fingerprint": fp, "rule_id": f.rule_id, "subject": f.subject, "severity": f.severity, "summary": f.summary,
                "evidence_class": f.evidence_class, "id": f.id}
        out["new" if fp not in fb else "persisting"].append(item)
        if f.evidence_class == "CONFIGURATION_RISK" and "RUNTIME_OBSERVATION" not in f.provenance:
            out["unverified"].append(item)
    for fp, f in fb.items():
        if fp not in fa:
            out["resolved"].append({"fingerprint": fp, "rule_id": f.rule_id, "subject": f.subject, "severity": f.severity,
                                    "summary": f.summary, "evidence_class": f.evidence_class, "id": f.id,
                                    "verified_by_runtime": after_has_runtime})
    return out


def drift_findings(diff: SnapshotDiff) -> list[Finding]:
    """RLS-018: turn risk-increasing structural changes and behavioural regressions into reviewable findings."""
    out: list[Finding] = []
    for c in diff.changes:
        if c.risk != "higher":
            continue
        fp = make_fingerprint("RLS-018", c.subject, c.category, c.kind, c.summary)
        out.append(Finding(
            id=make_id(fp, diff.to_hash[-8:]), fingerprint=fp, rule_id="RLS-018", title="Policy semantic drift across migrations",
            severity="Needs triage", severity_rationale="Heuristic risk direction from a structural diff; no runtime proof.",
            evidence_class="CONFIGURATION_RISK", provenance=["CATALOG_FACT", "STATIC_INFERENCE"], confidence="CONDITIONAL",
            subject=c.subject, summary=c.summary + (f" ({c.note})" if c.note else ""),
            why_it_matters="The change moves the authorization boundary in a direction that usually widens access. Re-run the matrix to see whether behaviour changed.",
            evidence=[EvidenceRef(kind="diff", ref=c.subject, summary=c.summary, provenance="STATIC_INFERENCE")], objects={"category": c.category},
            remediation="Review the change; add or update expectations and re-run the authorization matrix.",
            references=["https://www.postgresql.org/docs/current/ddl-rowsecurity.html"], verified_by="diff",
            limitations="A schema diff is not proof of an exploit or of behavioural equivalence.",
        ))
    for b in diff.behavioral:
        if b.transition != "regression":
            continue
        fp = make_fingerprint("RLS-018", b.case_id, "regression")
        out.append(Finding(
            id=make_id(fp, diff.to_hash[-8:]), fingerprint=fp, rule_id="RLS-018", title="Policy semantic drift across migrations",
            severity="High", severity_rationale="A test that previously did not fail now fails after the schema change (runtime evidence on both sides).",
            evidence_class="CONFIRMED_VIOLATION", provenance=["RUNTIME_OBSERVATION", "USER_EXPECTATION"], confidence="OBSERVED",
            subject=b.case_id, summary=f"Case {b.case_id} regressed {b.before} → {b.after}: {b.summary}",
            evidence=[EvidenceRef(kind="case", ref=b.case_id, summary=f"{b.before} → {b.after}", provenance="RUNTIME_OBSERVATION")],
            case_ids=[b.case_id], remediation="Revert or correct the policy change and re-run the case.",
            references=["https://www.postgresql.org/docs/current/ddl-rowsecurity.html"], verified_by="runtime_lab",
        ))
    return out
