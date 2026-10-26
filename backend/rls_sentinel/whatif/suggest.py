"""Reviewable remediation SQL suggestions. NEVER applied automatically - they are text for a human and a sandbox replay."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

from ..catalog.exprs import analyze_expression
from ..catalog.models import PolicyRec, Snapshot
from ..findings.models import Finding
from ..identifiers import parse_qualified

_SIMPLE = re.compile(r"^[a-z_][a-z0-9_$]*$")


def qi(name: str) -> str:
    return name if _SIMPLE.match(name) else '"' + name.replace('"', '""') + '"'


def qt(qualified: str) -> str:
    s, n = parse_qualified(qualified)
    return f"{qi(s)}.{qi(n)}"


def _roles(p: PolicyRec) -> str:
    return ", ".join("PUBLIC" if r == "PUBLIC" else qi(r) for r in p.roles)


class Suggestion(BaseModel):
    id: str
    finding_ids: list[str] = Field(default_factory=list)
    rule_id: str
    title: str
    sql: str
    rationale: str
    caveats: list[str] = Field(default_factory=list)
    confidence: str = "CONDITIONAL"  # a suggestion is only a hypothesis until the sandbox replay passes


def _tenant_sibling(snap: Snapshot, p: PolicyRec) -> PolicyRec | None:
    """A permissive, non-constant policy on the same table that covers the same command with a real predicate."""
    for q in snap.policies_for(p.table):
        if q.name == p.name or not q.permissive:
            continue
        expr = q.using_expr if p.command in ("SELECT", "UPDATE", "DELETE") else q.check_expr
        overlaps = set(q.roles) & set(p.roles) or q.roles == p.roles or "PUBLIC" in p.roles
        if q.command in (p.command, "ALL") and expr and not analyze_expression(expr).is_const_true and overlaps:
            return q
    return None


def build_suggestions(snap: Snapshot, findings: list[Finding]) -> list[Suggestion]:
    out: dict[str, Suggestion] = {}

    def put(key: str, fid: str, rule: str, title: str, sql: str, why: str, caveats: list[str] | None = None) -> None:
        if key in out:
            if fid not in out[key].finding_ids:
                out[key].finding_ids.append(fid)
            return
        out[key] = Suggestion(id=f"s{len(out) + 1}", finding_ids=[fid], rule_id=rule, title=title, sql=sql.strip() + "\n",
                              rationale=why, caveats=caveats or [])

    by_table_static: dict[str, list[Finding]] = {}
    for f in findings:
        if f.evidence_class != "CONFIRMED_VIOLATION" and f.objects.get("table"):
            by_table_static.setdefault(f.objects["table"], []).append(f)

    for f in findings:
        o: dict[str, Any] = f.objects
        r = f.rule_id
        if r == "RLS-001" and o.get("table"):
            t = qt(o["table"])
            put(f"enable:{t}", f.id, r, f"Enable RLS on {o['table']}", f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;",
                "Policies become active; with no policy the table denies access by default.",
                ["Existing roles lose access until policies exist: add policies in the same change.", "Verify with the authorization matrix."])
        elif r == "RLS-004" and o.get("owner") and o.get("table"):
            t = qt(o["table"])
            put(f"force:{t}", f.id, r, f"FORCE RLS on {o['table']}", f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY;",
                "The table owner becomes subject to the table's policies.", ["Does not affect superusers or BYPASSRLS roles.", "Owner-run migrations/jobs may need explicit policies."])
        elif r in ("RLS-002", "RLS-005") and o.get("policy") and o.get("table"):
            p = next((x for x in snap.policies if x.table == o["table"] and x.name == o["policy"]), None)
            if p is None:
                continue
            sib = _tenant_sibling(snap, p)
            t, n = qt(p.table), qi(p.name)
            if p.command == "INSERT" and sib and sib.check_expr:
                put(f"alter:{p.id}", f.id, r, f"Bound INSERT check of {p.name}", f"ALTER POLICY {n} ON {t}\n    WITH CHECK ({sib.check_expr});",
                    f"Copies the tenant predicate from policy {sib.name}.", [f"Expression copied from {sib.name}; confirm it matches the intended tenant boundary."])
            elif p.command in ("UPDATE", "ALL") and p.using_expr and p.check_expr is not None and analyze_expression(p.check_expr).is_const_true \
                    and not analyze_expression(p.using_expr).is_const_true:
                put(f"alter:{p.id}", f.id, r, f"Bound UPDATE check of {p.name}", f"ALTER POLICY {n} ON {t}\n    WITH CHECK ({p.using_expr});",
                    "Re-uses the policy's own USING predicate so rows cannot move to another tenant.", ["Review: some workflows legitimately re-assign rows."])
            elif sib is not None:
                expr = sib.using_expr if p.command in ("SELECT", "UPDATE", "DELETE") else sib.check_expr
                clause = "USING" if p.command in ("SELECT", "UPDATE", "DELETE") else "WITH CHECK"
                put(f"alter:{p.id}", f.id, r, f"Bound {p.command} policy {p.name}", f"ALTER POLICY {n} ON {t}\n    {clause} ({expr});",
                    f"Replaces the constant expression with the predicate of policy {sib.name}.", [f"Expression copied from {sib.name}; review."])
            elif p.using_expr and analyze_expression(p.using_expr).is_const_true:
                put(f"drop:{p.id}", f.id, r, f"Drop broad policy {p.name}", f"DROP POLICY {n} ON {t};",
                    "No tenant-bounded sibling exists to copy a predicate from; removing the broad policy restores default deny for the roles it served.",
                    ["Roles that legitimately relied on this policy will lose access - provide a bounded replacement."])
        elif r == "RLS-008" and o.get("view"):
            v = qt(o["view"])
            put(f"view:{v}", f.id, r, f"security_invoker on {o['view']}", f"ALTER VIEW {v} SET (security_invoker = true);",
                "Base-table access and RLS are evaluated for the caller instead of the view owner.",
                ["Callers need privileges on the base table's columns.", "Requires PostgreSQL 15 or later."])
        elif r == "RLS-009" and o.get("function"):
            fn = o["function"]
            s, rest = fn.split(".", 1)
            name, _, args = rest.partition("(")
            sig = f"{qi(s)}.{qi(name)}({args}"
            put(f"fn:{fn}", f.id, r, f"Make {fn} SECURITY INVOKER", f"ALTER FUNCTION {sig} SECURITY INVOKER;\nALTER FUNCTION {sig} SET search_path = pg_catalog, public;\nREVOKE EXECUTE ON FUNCTION {sig} FROM PUBLIC;",
                "Function runs with the caller's rights so RLS applies; search_path is pinned; PUBLIC loses EXECUTE.",
                ["Callers need table privileges.", "Re-grant EXECUTE only to the roles that need it."])
        elif r in ("RLS-010", "RLS-014") and o.get("table"):
            t = qt(o["table"])
            privs = o.get("privileges") or ([o["privilege"]] if o.get("privilege") else [])
            who = o.get("role") or ", ".join(o.get("grantees", []))
            if (privs and who and r == "RLS-014") or (r == "RLS-010" and f.severity == "Medium"):
                put(f"revoke:{t}:{who}:{','.join(privs)}", f.id, r, f"Revoke {', '.join(privs)} on {o['table']}",
                    f"REVOKE {', '.join(privs)} ON {t} FROM {who};", "Removes a privilege that RLS cannot govern.", ["Check that no job relies on it."])
        elif r == "RLS-011" and o.get("policy") and o.get("table"):
            p = next((x for x in snap.policies if x.table == o["table"] and x.name == o["policy"]), None)
            if p and p.permissive and p.using_expr:
                t, n = qt(p.table), qi(p.name)
                put(f"restrictive:{p.id}", f.id, r, f"Make {p.name} RESTRICTIVE",
                    f"DROP POLICY {n} ON {t};\nCREATE POLICY {n} ON {t} AS RESTRICTIVE FOR {p.command} TO {_roles(p)}\n    USING ({p.using_expr})"
                    + (f"\n    WITH CHECK ({p.check_expr})" if p.check_expr and p.command in ("UPDATE", "ALL", "INSERT") else "") + ";",
                    "PERMISSIVE policies are OR-ed with the rest and GRANT access; a restriction must be declared AS RESTRICTIVE so it is AND-ed.",
                    ["Keep at least one permissive policy per command, otherwise nothing is allowed.",
                     "The policy is dropped and re-created: run inside one transaction."])
        elif r == "RLS-003" and o.get("table") and o.get("privilege"):
            t = qt(o["table"])
            put(f"revokepub:{t}:{o['privilege']}", f.id, r, f"Revoke {o['privilege']} from PUBLIC", f"REVOKE {o['privilege']} ON {t} FROM PUBLIC;",
                "Grant explicitly to the roles that need it.", ["Grant the privilege to specific roles in the same change."])
    # Runtime-only confirmed findings: reuse the static suggestion(s) of the same table.
    for f in findings:
        if f.evidence_class == "CONFIRMED_VIOLATION" and f.objects.get("table"):
            for s in list(out.values()):
                fids = {x.id: x for x in by_table_static.get(f.objects["table"], [])}
                if any(fid in fids for fid in s.finding_ids) and f.id not in s.finding_ids:
                    s.finding_ids.append(f.id)
    return list(out.values())


def combine_sql(suggestions: list[Suggestion]) -> str:
    parts = ["-- RLS Sentinel: suggested remediation (REVIEW REQUIRED; never applied automatically)", "BEGIN;"]
    for s in suggestions:
        parts.append(f"\n-- {s.title}  [{s.rule_id}]\n-- {s.rationale}")
        parts += [f"-- caveat: {c}" for c in s.caveats]
        parts.append(s.sql.rstrip())
    parts.append("\nCOMMIT;")
    return "\n".join(parts) + "\n"
