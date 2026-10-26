"""Rule engine: turns catalog snapshots, specs and runtime results into explainable findings.

Design rules (see docs/evidence-model.md):
  * static rules emit ``CONFIGURATION_RISK`` / ``STATIC_INFERENCE`` with cautious severity and wording;
  * ``CONFIRMED_VIOLATION`` is only produced from a runtime case that FAILED against an independent expectation;
  * unknown context produces ``INCONCLUSIVE`` findings, never a pass.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..catalog.exprs import ExprInfo, analyze_expression
from ..catalog.models import PolicyRec, Snapshot
from ..expectations.models import Actor, Spec, TableConfig
from ..findings.models import (
    SEVERITY_ORDER,
    Confidence,
    EvidenceClass,
    EvidenceRef,
    Finding,
    Provenance,
    Severity,
    make_fingerprint,
    make_id,
)
from ..graph.roles import RoleGraph
from ..harness.results import CaseResult, RunResult
from .registry import RULES

WRITE_OPS = {"INSERT", "UPDATE", "DELETE", "UPSERT"}
CMD_APPLIES = {
    "SELECT": {"SELECT", "ALL"}, "INSERT": {"INSERT", "ALL"}, "UPDATE": {"UPDATE", "ALL"},
    "DELETE": {"DELETE", "ALL"},
}


class RuleEngine:
    def __init__(self, snapshot: Snapshot, spec: Spec | None = None, run: RunResult | None = None,
                 *, run_id: str | None = None):
        self.snap = snapshot
        self.spec = spec
        self.run = run
        self.run_id = run_id or (run.info.run_id if run else None)
        self.rg = RoleGraph(snapshot)
        self._expr: dict[str, ExprInfo] = {}
        self.findings: list[Finding] = []
        self.protected: dict[str, TableConfig | None] = self._protected_tables()
        self.candidate_mode = spec is None

    # ----------------------------------------------------------------- setup
    def _protected_tables(self) -> dict[str, TableConfig | None]:
        out: dict[str, TableConfig | None] = {}
        if self.spec is not None:
            for tc in self.spec.tables:
                if tc.protected:
                    out[tc.table] = tc
            for r in self.spec.resources:
                out.setdefault(r.table, self.spec.table_config(r.table))
            return out
        for t in self.snap.tables:
            if t.kind in ("table", "partitioned_table") and not t.extension_owned and any(c.tenant_candidate for c in t.columns):
                out[t.qualified] = None
        return out

    def expr(self, text: str | None) -> ExprInfo:
        key = text or ""
        if key not in self._expr:
            self._expr[key] = analyze_expression(text)
        return self._expr[key]

    # ------------------------------------------------------------------ build
    def _add(self, rule_id: str, subject: str, *, discr: tuple[str, ...] = (), severity: Severity,
             rationale: str, cls: EvidenceClass, prov: list[Any], conf: Confidence, summary: str,
             why: str = "", expected: str | None = None, observed: str | None = None,
             evidence: list[EvidenceRef] | None = None, case_ids: list[str] | None = None,
             objects: dict[str, Any] | None = None, repro: list[str] | None = None, remediation: str = "",
             limitations: str = "", verified_by: str = "catalog", location: dict | None = None,
             title: str | None = None) -> Finding:
        meta = RULES[rule_id]
        fp = make_fingerprint(rule_id, subject, *discr)
        f = Finding(
            id=make_id(fp, self.run_id), fingerprint=fp, rule_id=rule_id, title=title or meta.title,
            severity=severity, severity_rationale=rationale, evidence_class=cls, provenance=prov, confidence=conf,
            subject=subject, summary=summary, why_it_matters=why, expected=expected, observed=observed,
            evidence=evidence or [], case_ids=case_ids or [], objects=objects or {}, reproduction=repro or [],
            remediation=remediation or meta.remediation, references=list(meta.references),
            limitations=limitations, verified_by=verified_by,  # type: ignore[arg-type]
            location=location,
        )
        self.findings.append(f)
        return f

    def _cat_ref(self, rec: Any, summary: str) -> EvidenceRef:
        ref = getattr(getattr(rec, "provenance", None), "ref", None) or getattr(rec, "id", "catalog")
        return EvidenceRef(kind="catalog", ref=str(ref), summary=summary, provenance="CATALOG_FACT")

    def _loc(self, rec: Any) -> dict | None:
        p = getattr(rec, "provenance", None)
        if p is not None and p.path:
            return {"path": p.path, "line": p.line}
        return None

    def _app_roles_for(self, table: str) -> list[str]:
        """Non-system, non-privileged roles that hold any effective privilege on the table (database-computed)."""
        out = []
        for role, rels in self.snap.effective_table_privileges.items():
            r = self.rg.roles.get(role)
            if r is None or r.system or r.superuser or r.bypassrls:
                continue
            t = self.snap.table(table)
            if t and self.rg.owner_effective(role, table):
                continue
            if rels.get(table):
                out.append(role)
        return sorted(out)

    def _actor_roles_expected_bounded(self) -> set[str]:
        """DB roles of actors that the spec expects to be tenant-bounded (users/anonymous)."""
        if not self.spec:
            return set()
        return {a.pg_role for a in self.spec.actors if a.kind in ("user", "anonymous") and not a.expect_bypass}

    # ================================================================ static rules
    def run_static(self) -> None:
        self.rls001()
        self.rls002()
        self.rls003()
        self.rls004_static()
        self.rls005_static()
        self.rls008_static()
        self.rls009_static()
        self.rls010_static()
        self.rls011_static()
        self.rls012_static()
        self.rls013_static()
        self.rls014()
        self.rls016_static()
        self.rls019_static()
        self.rls020_static()

    # RLS-001 --------------------------------------------------------------------------------------
    def rls001(self) -> None:
        for q in self.protected:
            t = self.snap.table(q)
            if t is None or t.kind not in ("table", "partitioned_table") or t.rls_enabled:
                continue
            roles = self._app_roles_for(q)
            pols = self.snap.policies_for(q)
            declared = not self.candidate_mode
            if declared:
                sev: Severity = "High" if roles else "Low"
                why = (f"{len(roles)} non-owner role(s) hold SQL privileges ({', '.join(roles[:5])}); without RLS those grants expose every row."
                       if roles else "No non-owner role currently holds privileges, so exposure is limited to the owner and superusers.")
                cls: EvidenceClass = "CONFIGURATION_RISK"
                prov: list[Provenance] = ["CATALOG_FACT", "USER_EXPECTATION"]
                conf: Confidence = "ESTABLISHED"
                rationale = "RLS is disabled on a table the expected-policy spec declares protected" + (
                    "; non-owner roles hold privileges." if roles else "; no non-owner privileges found.")
            else:
                if not roles:
                    continue
                sev = "Needs triage"
                why = "The table has a tenant-like column and non-owner grants but RLS is disabled. Without a declared expectation this is only a candidate."
                cls, prov, conf = "CONFIGURATION_RISK", ["CATALOG_FACT", "STATIC_INFERENCE"], "CONDITIONAL"
                rationale = "No expected-policy spec supplied; protection intent is inferred from column names only."
            summary = f"Row-level security is disabled on {q}." + (
                f" {len(pols)} polic{'y exists' if len(pols) == 1 else 'ies exist'} but {'is' if len(pols) == 1 else 'are'} inactive." if pols else "")
            self._add("RLS-001", q, severity=sev, rationale=rationale, cls=cls, prov=prov, conf=conf, summary=summary, why=why,
                      evidence=[self._cat_ref(t, "relrowsecurity = false")], objects={"table": q, "roles": roles},
                      remediation=f"ALTER TABLE {q} ENABLE ROW LEVEL SECURITY; then define explicit policies. "
                                  "A table with RLS enabled and no policy denies access by default.",
                      limitations="Catalog inspection cannot prove that data is actually exposed; run the behavioral lab to confirm.",
                      verified_by="catalog", location=self._loc(t))

    # RLS-002 --------------------------------------------------------------------------------------
    def rls002(self) -> None:
        bounded = self._actor_roles_expected_bounded()
        for p in self.snap.policies:
            if p.table not in self.protected or not p.permissive:
                continue
            u, c = self.expr(p.using_expr), self.expr(p.check_expr)
            broad_using = p.command in ("SELECT", "UPDATE", "DELETE", "ALL") and u.is_const_true
            broad_check = p.command in ("INSERT", "UPDATE", "ALL") and c.is_const_true and p.command != "ALL"
            if not (broad_using or broad_check):
                continue
            applies = self.rg.applicable_roles(p.roles)
            hit = sorted(applies & bounded) if self.spec else sorted(applies)
            if self.spec and not hit:
                continue  # broad policy limited to roles the spec treats as intentionally broad (e.g. support)
            tc = self.protected.get(p.table)
            sev: Severity = "Medium" if self.spec else "Needs triage"
            self._add(
                "RLS-002", p.id, severity=sev,
                rationale=("Constant-TRUE permissive policy reachable by roles the spec expects to be tenant-bounded; not runtime-confirmed."
                           if self.spec else "No expectation spec: cannot tell whether broad access is intended."),
                cls="CONFIGURATION_RISK", prov=["CATALOG_FACT", "STATIC_INFERENCE"] + (["USER_EXPECTATION"] if self.spec else []),
                conf="CONDITIONAL",
                summary=f"Permissive {p.command} policy \"{p.name}\" on {p.table} is constant TRUE and applies to {', '.join(p.roles)}.",
                why="Permissive policies are OR-ed: one constant-TRUE policy cancels the tenant predicate of every other permissive policy for the same command.",
                expected=f"rows bounded by {tc.tenant_column}" if tc and tc.tenant_column else None,
                evidence=[self._cat_ref(p, f"USING {p.using_expr} / WITH CHECK {p.check_expr}")],
                objects={"table": p.table, "policy": p.name, "roles": hit or p.roles},
                limitations="Whether the extra access is reachable depends on SQL grants and other restrictive policies; confirm with a runtime case.",
                location=self._loc(p),
            )

    # RLS-003 --------------------------------------------------------------------------------------
    def rls003(self) -> None:
        for p in self.snap.policies:
            if p.table in self.protected and p.roles == ["PUBLIC"] and p.permissive:
                u = self.expr(p.using_expr)
                if u.negative_filter and not u.is_const_true:
                    continue  # reported by RLS-011 as a probable mis-declared restriction
                sel = u.is_const_true or p.using_expr is None
                self._add("RLS-003", p.id, discr=("policy",),
                          severity=("Medium" if self.spec else "Needs triage") if sel else "Informational",
                          rationale="Permissive policy with a constant-TRUE filter targets PUBLIC (every role) on a protected table."
                          if sel else "PUBLIC-scoped policy with a selective expression: verify that every role may use it.",
                          cls="CONFIGURATION_RISK", prov=["CATALOG_FACT", "STATIC_INFERENCE"], conf="ESTABLISHED",
                          summary=f"Permissive {p.command} policy \"{p.name}\" on {p.table} applies to PUBLIC (all roles).",
                          why="PUBLIC includes every role that exists now or is created later, including low-privilege and anonymous roles.",
                          evidence=[self._cat_ref(p, "polroles = {0}")], objects={"table": p.table, "policy": p.name},
                          location=self._loc(p))
        for g in self.snap.grants:
            if g.object_type == "table" and g.grantee == "PUBLIC" and g.object in self.protected:
                t = self.snap.table(g.object)
                if t and t.kind in ("table", "partitioned_table"):
                    self._add("RLS-003", f"{g.object}:{g.privilege}", discr=("grant",),
                              severity=("Low" if t.rls_enabled else "Medium") if self.spec else "Needs triage",
                              rationale="Table privilege granted to PUBLIC on a protected table.",
                              cls="CONFIGURATION_RISK", prov=["CATALOG_FACT"], conf="ESTABLISHED",
                              summary=f"{g.privilege} on {g.object} is granted to PUBLIC.",
                              why="Every role can reach the table; only RLS policies (if any) remain between it and the data.",
                              evidence=[self._cat_ref(g, "ACL entry grantee = PUBLIC")], objects={"table": g.object, "privilege": g.privilege},
                              remediation=f"REVOKE {g.privilege} ON {g.object} FROM PUBLIC; grant it to explicit roles.")

    # RLS-004 (static) ---------------------------------------------------------------------------------
    def rls004_static(self) -> None:
        mapped = {a.pg_role for a in self.spec.actors if not a.expect_bypass} if self.spec else set()
        for r in self.snap.roles:
            if r.system or not (r.superuser or r.bypassrls):
                continue
            if self.snap.source.kind == "fixture" and r.name == "sentinel_admin":
                continue  # lab infrastructure account of the disposable server
            in_spec = r.name in mapped
            why = ("The role is mapped to an application actor in the spec but bypasses RLS: its sessions never evaluate policies."
                   if in_spec else "Bypassing roles are legitimate for administration; ensure no application path connects as this role.")
            self._add("RLS-004", f"role:{r.name}", severity="High" if in_spec else "Informational",
                      rationale="Role bypasses RLS and is mapped to an application actor." if in_spec else
                      "Administrative bypass role: expected in most deployments; no application mapping known.",
                      cls="CONFIGURATION_RISK", prov=["CATALOG_FACT"] + (["USER_EXPECTATION"] if in_spec else []),
                      conf="ESTABLISHED",
                      summary=f"Role {r.name} {'is a superuser' if r.superuser else 'has BYPASSRLS'}"
                              f"{' and can log in' if r.login else ''}.",
                      why=why, evidence=[self._cat_ref(r, "rolsuper/rolbypassrls")], objects={"role": r.name})
        for q in self.protected:
            t = self.snap.table(q)
            if not t or not t.rls_enabled or t.rls_forced or t.kind not in ("table", "partitioned_table"):
                continue
            owner = self.rg.roles.get(t.owner)
            if owner is None:
                continue
            mapped_owner = t.owner in mapped or any(self.rg.owner_effective(a, q) for a in mapped)
            if not (owner.login or mapped_owner):
                continue
            self._add("RLS-004", f"{q}:owner", discr=("owner",), severity="Medium" if mapped_owner else "Needs triage",
                      rationale="Owner bypasses RLS (no FORCE) and the owner role is login-capable or mapped to an actor.",
                      cls="CONFIGURATION_RISK", prov=["CATALOG_FACT", "STATIC_INFERENCE"], conf="CONDITIONAL",
                      summary=f"Owner {t.owner} of {q} bypasses RLS because FORCE ROW LEVEL SECURITY is off.",
                      why="Code that connects as the table owner is never subject to its policies.",
                      evidence=[self._cat_ref(t, "relforcerowsecurity = false")], objects={"table": q, "owner": t.owner},
                      remediation=f"ALTER TABLE {q} FORCE ROW LEVEL SECURITY; (and keep application sessions off the owner role).",
                      limitations="FORCE does not affect superusers or BYPASSRLS roles.")

    # RLS-005 (static) ---------------------------------------------------------------------------------
    def rls005_static(self) -> None:
        for p in self.snap.policies:
            if p.table not in self.protected or not p.permissive:
                continue
            tc = self.protected[p.table]
            tcol = tc.tenant_column if tc else None
            c, u = self.expr(p.check_expr), self.expr(p.using_expr)
            reason = None
            if p.command == "INSERT" and c.is_const_true:
                reason = "INSERT WITH CHECK is constant TRUE: any permitted role may insert rows for any tenant."
            elif p.command in ("UPDATE", "ALL") and p.check_expr is not None and c.is_const_true and not u.is_const_true:
                reason = "UPDATE WITH CHECK is constant TRUE while USING is restrictive: a role can update a visible row into another tenant."
            elif p.command in ("INSERT", "UPDATE") and tcol and p.check_expr is not None and not c.parse_error and \
                    not c.is_const_true and tcol not in c.columns and not c.has_sublink and tcol in u.columns:
                reason = f"WITH CHECK does not reference the tenant column {tcol} although USING does."
            if not reason:
                continue
            self._add("RLS-005", p.id, severity="Medium" if self.spec else "Needs triage",
                      rationale="Static: the new-row guard is absent or ineffective by expression. Other policies (for example the SELECT policy) may still block the write at runtime.",
                      cls="CONFIGURATION_RISK", prov=["CATALOG_FACT", "STATIC_INFERENCE"], conf="CONDITIONAL",
                      summary=f"{p.command} policy \"{p.name}\" on {p.table}: {reason}",
                      why="WITH CHECK validates the proposed new row; without a tenant-bound check rows can be created in, or moved to, other tenants.",
                      evidence=[self._cat_ref(p, f"WITH CHECK {p.check_expr}")], objects={"table": p.table, "policy": p.name},
                      limitations="Runtime behaviour also depends on SELECT policies (PostgreSQL re-checks visibility of updated rows) - use the lab to confirm.",
                      location=self._loc(p))

    # RLS-008 (static) ---------------------------------------------------------------------------------
    def rls008_static(self) -> None:
        for t in self.snap.tables:
            if not t.is_view or t.extension_owned or t.security_invoker:
                continue
            bases = [b for b in t.view_depends_on if b in self.protected]
            if not bases:
                continue
            exposed = []
            for b in bases:
                base = self.snap.table(b)
                if base is None or not base.rls_enabled:
                    continue
                why_bypass = self.rg.bypasses_rls(t.owner, b)
                if why_bypass:
                    exposed.append((b, why_bypass))
            if not exposed:
                continue
            readers = self._readers(t.qualified)
            if not readers:
                continue
            b, why_bypass = exposed[0]
            self._add("RLS-008", t.qualified, severity="Medium" if self.spec else "Needs triage",
                      rationale="View runs with its owner's rights and the owner bypasses RLS on the base table; roles can read the view. Not runtime-confirmed.",
                      cls="CONFIGURATION_RISK", prov=["CATALOG_FACT", "STATIC_INFERENCE"], conf="CONDITIONAL",
                      summary=f"View {t.qualified} (owner {t.owner}, no security_invoker) reads {b}, and its owner bypasses RLS there ({why_bypass}).",
                      why="Row policies on the base table are evaluated for the view owner, not for the caller, so the view can return every tenant's rows.",
                      evidence=[self._cat_ref(t, "reloptions has no security_invoker"), EvidenceRef(kind="catalog", ref=b, summary=f"base table, owner bypass: {why_bypass}")],
                      objects={"view": t.qualified, "base": b, "readers": readers},
                      remediation=f"ALTER VIEW {t.qualified} SET (security_invoker = true);",
                      limitations="The view may filter rows itself (WHERE tenant = ...); only a runtime case can show actual leakage.",
                      location=self._loc(t))

    def _readers(self, table: str) -> list[str]:
        out = []
        for role, rels in self.snap.effective_table_privileges.items():
            r = self.rg.roles.get(role)
            if r is None or r.system or r.superuser or r.bypassrls:
                continue
            t = self.snap.table(table)
            if t and role == t.owner:
                continue
            if "SELECT" in rels.get(table, []):
                out.append(role)
        return sorted(out)

    # RLS-009 (static) ---------------------------------------------------------------------------------
    def rls009_static(self) -> None:
        for fn in self.snap.functions:
            if not fn.security_definer or fn.extension_owned:
                continue
            owner = self.rg.roles.get(fn.owner)
            owner_bypass = bool(owner and (owner.superuser or owner.bypassrls))
            protected_owned = [q for q in self.protected if (t := self.snap.table(q)) and self.rg.owner_effective(fn.owner, q) and not t.rls_forced and t.rls_enabled]
            if not (owner_bypass or protected_owned):
                continue
            executors = sorted(r for r, fns in self.snap.effective_function_execute.items()
                               if fn.qualified in fns and r != fn.owner and not (self.rg.roles.get(r) and (self.rg.roles[r].superuser or self.rg.roles[r].bypassrls)))
            if not executors:
                continue
            fixed = fn.has_fixed_search_path
            sev: Severity = "Needs triage" if not fixed else "Low"
            self._add("RLS-009", fn.qualified, severity=sev,
                      rationale="Candidate only: SECURITY DEFINER + owner bypasses RLS + callable by other roles. Function bodies are not analysed, so leakage is unproven." + (" search_path is pinned." if fixed else " search_path is NOT pinned."),
                      cls="CONFIGURATION_RISK", prov=["CATALOG_FACT", "STATIC_INFERENCE"], conf="CONDITIONAL",
                      summary=f"SECURITY DEFINER function {fn.qualified} (owner {fn.owner}) can be executed by {', '.join(executors[:6])}{'…' if len(executors) > 6 else ''}"
                              f"{' and PUBLIC' if fn.public_execute else ''}; its owner bypasses RLS on protected tables.",
                      why="The function body runs with the owner's rights; if it reads tenant tables without checking the caller, RLS is bypassed through the function." +
                          ("" if fixed else " Without a fixed search_path, object resolution is also hijackable."),
                      evidence=[self._cat_ref(fn, "prosecdef = true"), EvidenceRef(kind="catalog", ref=fn.provenance.ref or fn.qualified, summary=f"EXECUTE: {'PUBLIC' if fn.public_execute else ', '.join(executors[:4])}")],
                      objects={"function": fn.qualified, "owner": fn.owner, "executors": executors, "search_path_pinned": fixed},
                      remediation=f"Prefer SECURITY INVOKER. If DEFINER is required: ALTER FUNCTION {fn.qualified} SET search_path = pg_catalog, public; "
                                  f"REVOKE EXECUTE ON FUNCTION {fn.qualified} FROM PUBLIC; and check the caller's tenant inside the body.",
                      limitations="Not all SECURITY DEFINER functions are vulnerable. Add an EXECUTE expectation to confirm behaviour at runtime.",
                      location=self._loc(fn))

    # RLS-010 (static, spec privileges) ------------------------------------------------------------------
    def rls010_static(self) -> None:
        if not self.spec:
            return
        for i, pe in enumerate(self.spec.privileges):
            effective = self._effective(pe.role, pe.table)
            if effective is None:
                continue
            unexpected = sorted(set(pe.deny) & effective)
            missing = sorted(set(pe.allow) - effective)
            pid = pe.id or f"privileges.{i}"
            if unexpected:
                self._add("RLS-010", f"{pe.role}@{pe.table}", discr=("unexpected", ",".join(unexpected)),
                          severity="Medium", rationale="Catalog-verified privilege that the spec explicitly denies.",
                          cls="CONFIGURATION_RISK", prov=["CATALOG_FACT", "USER_EXPECTATION"], conf="ESTABLISHED",
                          summary=f"Role {pe.role} holds unexpected privilege(s) {', '.join(unexpected)} on {pe.table}.",
                          why="SQL privileges are the first gate; privileges the design does not need widen what RLS alone must contain.",
                          expected=f"deny {', '.join(pe.deny)}", observed=f"effective {', '.join(sorted(effective)) or 'none'}",
                          evidence=[EvidenceRef(kind="spec", ref=pid, summary="expectation", provenance="USER_EXPECTATION"),
                                    EvidenceRef(kind="catalog", ref=f"has_table_privilege({pe.role}, {pe.table})", summary=", ".join(unexpected))],
                          objects={"role": pe.role, "table": pe.table, "privileges": unexpected},
                          remediation="; ".join(f"REVOKE {u} ON {pe.table} FROM {pe.role}" for u in unexpected) + ";")
            if missing:
                self._add("RLS-010", f"{pe.role}@{pe.table}", discr=("missing", ",".join(missing)),
                          severity="Low", rationale="Expected privilege is absent: availability issue, not exposure.",
                          cls="CONFIGURATION_RISK", prov=["CATALOG_FACT", "USER_EXPECTATION"], conf="ESTABLISHED",
                          summary=f"Role {pe.role} lacks expected privilege(s) {', '.join(missing)} on {pe.table}.",
                          expected=f"allow {', '.join(pe.allow)}", observed=f"effective {', '.join(sorted(effective)) or 'none'}",
                          evidence=[EvidenceRef(kind="spec", ref=pid, summary="expectation", provenance="USER_EXPECTATION")],
                          objects={"role": pe.role, "table": pe.table, "privileges": missing},
                          remediation="; ".join(f"GRANT {m} ON {pe.table} TO {pe.role}" for m in missing) + ";")

    def _effective(self, role: str, table: str) -> set[str] | None:
        from ..identifiers import parse_qualified

        s, n = parse_qualified(table)
        q = f"{s}.{n}"
        if self.snap.table(q) is None:
            return None
        if role == "PUBLIC":
            return {g.privilege for g in self.snap.grants if g.object_type == "table" and g.object == q and g.grantee == "PUBLIC"}
        if role not in self.rg.roles:
            return None
        got = set(self.snap.effective_table_privileges.get(role, {}).get(q) or [])
        if self.snap.effective_column_select.get(role, {}).get(q):
            got.add("SELECT")  # column-level SELECT exposes (some) data even without a table-level grant
        return got

    # RLS-011 (static) ---------------------------------------------------------------------------------
    def rls011_static(self) -> None:
        by: dict[tuple[str, str], list[PolicyRec]] = defaultdict(list)
        for p in self.snap.policies:
            if p.table in self.protected:
                for cmd in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                    if p.command in CMD_APPLIES[cmd]:
                        by[(p.table, cmd)].append(p)
        reported: set[str] = set()
        for (table, cmd), pols in sorted(by.items()):
            perm = [p for p in pols if p.permissive]
            restr = [p for p in pols if not p.permissive]
            if restr and not perm:
                key = f"{table}:{cmd}:restrictive-only"
                if key in reported:
                    continue
                reported.add(key)
                self._add("RLS-011", f"{table}:{cmd}", discr=("restrictive-only",), severity="Informational",
                          rationale="Informational: with only RESTRICTIVE policies no row can ever be granted for this command.",
                          cls="CONFIGURATION_RISK", prov=["CATALOG_FACT"], conf="ESTABLISHED",
                          summary=f"{table} has only restrictive {cmd} policies ({', '.join(p.name for p in restr)}): all {cmd} access is denied by default.",
                          why="A restrictive policy only narrows what permissive policies allow; with no permissive policy nothing is allowed.",
                          evidence=[self._cat_ref(p, "polpermissive = false") for p in restr[:3]], objects={"table": table, "command": cmd})
            for p in perm:
                u = self.expr(p.using_expr)
                if u.negative_filter and not u.is_const_true and len(perm) > 1 and p.command in ("SELECT", "UPDATE", "DELETE"):
                    key = f"{p.id}:negated"
                    if key in reported:
                        continue
                    reported.add(key)
                    self._add("RLS-011", p.id, discr=("negated-permissive",), severity="Needs triage",
                              rationale="Heuristic on the parsed expression: a purely negated predicate in a PERMISSIVE policy usually expresses a restriction.",
                              cls="CONFIGURATION_RISK", prov=["CATALOG_FACT", "STATIC_INFERENCE"], conf="CONDITIONAL",
                              summary=f"PERMISSIVE {p.command} policy \"{p.name}\" on {p.table} has a negated predicate ({p.using_expr}); it GRANTS every row that does not match instead of restricting them.",
                              why="Policies default to PERMISSIVE and are OR-ed with the rest. If the intent was 'hide archived/held rows', the policy must be declared AS RESTRICTIVE.",
                              evidence=[self._cat_ref(p, f"permissive, USING {p.using_expr}")],
                              objects={"table": p.table, "policy": p.name, "command": p.command},
                              remediation=f"ALTER POLICY cannot change PERMISSIVE/RESTRICTIVE: DROP POLICY {p.name} ON {p.table}; "
                                          f"CREATE POLICY {p.name} ON {p.table} AS RESTRICTIVE FOR {p.command} TO {', '.join(p.roles)} USING ({p.using_expr});",
                              limitations="Intent cannot be proven from catalog data; confirm with a runtime case.",
                              location=self._loc(p))
            for p in restr:
                u = self.expr(p.using_expr)
                if u.is_const_false:
                    self._add("RLS-011", p.id, discr=("restrictive-false",), severity="Informational",
                              rationale="A restrictive policy that is constant FALSE denies every row for the roles it applies to.",
                              cls="CONFIGURATION_RISK", prov=["CATALOG_FACT"], conf="ESTABLISHED",
                              summary=f"Restrictive policy \"{p.name}\" on {p.table} is constant FALSE for {', '.join(p.roles)}.",
                              evidence=[self._cat_ref(p, "restrictive, USING false")], objects={"table": p.table, "policy": p.name})

    # RLS-012 (static) ---------------------------------------------------------------------------------
    def rls012_static(self) -> None:
        for p in self.snap.policies:
            if p.table not in self.protected:
                continue
            roles = self.rg.applicable_roles(p.roles)
            relations = {r for r in p.deps.relations if r != p.table}
            for role in sorted(roles):
                rr = self.rg.roles[role]
                if rr.superuser or rr.bypassrls or self.rg.owner_effective(role, p.table):
                    continue
                if not self.snap.effective_table_privileges.get(role, {}).get(p.table):
                    continue  # the role cannot reach the table anyway
                missing = [rel for rel in relations if "SELECT" not in self.snap.effective_table_privileges.get(role, {}).get(rel, [])]
                if not missing:
                    continue
                usage = self.snap.schema_usage.get(role, [])
                self._add("RLS-012", f"{p.id}@{role}", severity="Medium",
                          rationale="Policy dependency lacks SELECT for a role that can reach the table: evaluation will raise 42501. Derived from catalog privileges, not executed.",
                          cls="CONFIGURATION_RISK", prov=["CATALOG_FACT", "STATIC_INFERENCE"], conf="ESTABLISHED",
                          summary=f"Policy \"{p.name}\" on {p.table} reads {', '.join(missing)}, but role {role} has no SELECT there.",
                          why="Policy subqueries run with the invoker's privileges. A missing grant surfaces as permission denied (42501), which looks like a denial but is a configuration error.",
                          evidence=[self._cat_ref(p, f"depends on {', '.join(missing)}")], objects={"policy": p.name, "table": p.table, "role": role, "missing": missing, "schema_usage": usage},
                          remediation="; ".join(f"GRANT SELECT ON {m} TO {role}" for m in missing) + ";", location=self._loc(p))
                break  # one finding per policy is enough

    # RLS-013 (static) ---------------------------------------------------------------------------------
    def rls013_static(self) -> None:
        for p in self.snap.policies:
            if p.table not in self.protected:
                continue
            keys: set[str] = set()
            for e in (p.using_expr, p.check_expr):
                keys |= set(self.expr(e).guc_keys)
            if self.expr(p.using_expr).null_identity_test or self.expr(p.check_expr).null_identity_test:
                self._add("RLS-013", p.id, discr=("null-identity",), severity="Medium" if self.spec else "Needs triage",
                          rationale="Static: the expression tests an identity function IS NULL; if that opens access, a request that lost its identity sees data.",
                          cls="CONFIGURATION_RISK", prov=["CATALOG_FACT", "STATIC_INFERENCE"], conf="CONDITIONAL",
                          summary=f"Policy \"{p.name}\" on {p.table} contains an \"identity IS NULL\" branch: {p.using_expr or p.check_expr}",
                          why="Missing or stripped identity context must deny access. An OR branch on a NULL identity turns a lost claim into an open door.",
                          evidence=[self._cat_ref(p, str(p.using_expr or p.check_expr))], objects={"table": p.table, "policy": p.name},
                          limitations="Needs a runtime case with an actor that carries no subject claim to confirm.", location=self._loc(p))
            custom = sorted(k for k in keys if not k.startswith(("request.jwt", "request.headers", "request.cookie")))
            jwt = sorted(k for k in keys if k.startswith("request.jwt"))
            if custom:
                self._add("RLS-013", p.id, discr=("custom-guc",), severity="Needs triage",
                          rationale="Static warning: identity read from a custom session setting. Any client that can run SQL can set it.",
                          cls="CONFIGURATION_RISK", prov=["CATALOG_FACT", "STATIC_INFERENCE"], conf="CONDITIONAL",
                          summary=f"Policy \"{p.name}\" on {p.table} trusts custom setting(s) {', '.join(custom)} for identity.",
                          why="set_config()/SET are available to every role. If an untrusted client can issue SQL, it can impersonate any tenant.",
                          evidence=[self._cat_ref(p, f"current_setting({', '.join(custom)})")], objects={"table": p.table, "policy": p.name, "settings": custom},
                          limitations="Becomes a proven weakness only with a forged-value runtime case (claims_override) AND untrusted SQL access. A static warning is not a vulnerability by itself.",
                          location=self._loc(p))
            elif jwt:
                self._add("RLS-013", p.id, discr=("jwt-guc",), severity="Informational",
                          rationale="Policy depends on gateway-set JWT settings: sound only if the gateway verifies the JWT and clients cannot SET these values.",
                          cls="INCONCLUSIVE", prov=["CATALOG_FACT", "STATIC_INFERENCE"], conf="ASSUMED",
                          summary=f"Policy \"{p.name}\" on {p.table} relies on {', '.join(jwt)} set by an external gateway.",
                          evidence=[self._cat_ref(p, f"current_setting({', '.join(jwt)})")], objects={"table": p.table, "policy": p.name, "settings": jwt},
                          limitations="Platform-side JWT verification cannot be observed from the database.", location=self._loc(p))

    # RLS-014 ----------------------------------------------------------------------------------------
    def rls014(self) -> None:
        for q in self.protected:
            t = self.snap.table(q)
            if t is None or t.kind not in ("table", "partitioned_table"):
                continue
            for priv, sev in (("TRUNCATE", "Medium"), ("REFERENCES", "Low"), ("TRIGGER", "Low")):
                grantees = sorted({g.grantee for g in self.snap.grants if g.object_type == "table" and g.object == q and g.privilege == priv
                                   and g.grantee != t.owner and not (self.rg.roles.get(g.grantee) and (self.rg.roles[g.grantee].superuser))})
                if not grantees:
                    continue
                why = {"TRUNCATE": "TRUNCATE removes every row of the table in one statement and is not subject to row policies.",
                       "REFERENCES": "REFERENCES allows creating foreign keys whose checks can reveal whether values exist (an information side channel) regardless of row policies.",
                       "TRIGGER": "TRIGGER allows attaching trigger code to the table, outside the reach of row policies."}[priv]
                self._add("RLS-014", f"{q}:{priv}", discr=(priv,), severity=sev,  # type: ignore[arg-type]
                          rationale=f"Catalog-verified {priv} grant to a non-owner role on a protected table; independent of RLS.",
                          cls="CONFIGURATION_RISK", prov=["CATALOG_FACT"], conf="ESTABLISHED",
                          summary=f"{priv} on {q} is granted to {', '.join(grantees)}.", why=why,
                          evidence=[EvidenceRef(kind="catalog", ref=f"{q} ACL", summary=f"{priv} -> {', '.join(grantees)}")],
                          objects={"table": q, "privilege": priv, "grantees": grantees},
                          remediation=f"REVOKE {priv} ON {q} FROM {', '.join(grantees)};",
                          limitations="This is a privilege finding, not an RLS bypass.", location=self._loc(t))

    # RLS-016 (static) ---------------------------------------------------------------------------------
    def rls016_static(self) -> None:
        if not self.spec:
            return
        for tc in self.spec.tables:
            for sc in tc.sensitive_columns:
                allowed_closure: set[str] = set()
                for ar in sc.allowed_roles:
                    allowed_closure |= self.rg.inheritors(ar)
                exposed = []
                for role, rels in self.snap.effective_table_privileges.items():
                    rr = self.rg.roles.get(role)
                    if rr is None or rr.system or rr.superuser or rr.bypassrls or role in allowed_closure:
                        continue
                    t = self.snap.table(tc.table)
                    if t is None or self.rg.owner_effective(role, tc.table):
                        continue
                    table_level = "SELECT" in rels.get(tc.table, [])
                    col_level = sc.column in self.snap.effective_column_select.get(role, {}).get(tc.table, [])
                    if table_level or col_level:
                        exposed.append(role)
                if exposed:
                    self._add("RLS-016", f"{tc.table}.{sc.column}", discr=("static",), severity="Medium",
                              rationale="Catalog-verified SELECT on a column the spec restricts, for roles outside the allowed list. Row visibility still depends on policies.",
                              cls="CONFIGURATION_RISK", prov=["CATALOG_FACT", "USER_EXPECTATION"], conf="ESTABLISHED",
                              summary=f"Column {tc.table}.{sc.column} is readable by {', '.join(exposed[:6])}{'…' if len(exposed) > 6 else ''}, outside the allowed roles {sc.allowed_roles or 'none'}.",
                              why="Row-level policies decide which rows are visible, not which columns; a sensitive column needs its own column-level GRANT.",
                              evidence=[EvidenceRef(kind="spec", ref=f"{tc.table}.{sc.column}", summary="sensitive_columns", provenance="USER_EXPECTATION")],
                              objects={"table": tc.table, "column": sc.column, "roles": exposed},
                              remediation=f"REVOKE SELECT ON {tc.table} FROM {', '.join(exposed)}; GRANT SELECT (<non-sensitive columns>) ON {tc.table} TO {', '.join(exposed)};")

    # RLS-019 (static) ---------------------------------------------------------------------------------
    def rls019_static(self) -> None:
        if self.spec is None:
            return
        modelled_claims = any(a.claims for a in self.spec.actors)
        for p in self.snap.policies:
            if p.table not in self.protected:
                continue
            ids: set[str] = set()
            for e in (p.using_expr, p.check_expr):
                x = self.expr(e)
                ids |= {i for i in x.identity_sources if i not in ("current_user", "session_user", "current_role", "user")}
            if ids and self.spec.identity_mode == "postgres_roles" and not modelled_claims:
                self._add("RLS-019", p.id, severity="Informational",
                          rationale="The policy reads session identity that this spec does not model; its outcome for real sessions is unknown.",
                          cls="INCONCLUSIVE", prov=["CATALOG_FACT", "STATIC_INFERENCE"], conf="ASSUMED",
                          summary=f"Policy \"{p.name}\" on {p.table} depends on {', '.join(sorted(ids))} but the spec uses identity_mode postgres_roles with no claims.",
                          why="Role-only tests cannot exercise claim-dependent policies; the missing context must be reported as unknown, not safe.",
                          evidence=[self._cat_ref(p, ", ".join(sorted(ids)))], objects={"table": p.table, "policy": p.name},
                          remediation="Use identity_mode: supabase_synthetic with explicit claims for actors (test-only), or add an authenticated HTTP adapter check.")

    # RLS-020 (static coverage) --------------------------------------------------------------------------
    def rls020_static(self) -> None:
        if self.spec is None:
            return
        covered: dict[str, set[str]] = defaultdict(set)
        for e in self.spec.expectations:
            res = self.spec.resource(e.resource) if e.resource else None
            tbl = e.table or (res.table if res else None)
            if tbl:
                op = "UPDATE" if e.operation == "UPSERT" else e.operation
                covered[tbl].add(op)
                if e.operation == "UPSERT":
                    covered[tbl].add("INSERT")
        for q in self.protected:
            t = self.snap.table(q)
            if t is None or t.kind not in ("table", "partitioned_table"):
                continue
            missing = [op for op in ("SELECT", "INSERT", "UPDATE", "DELETE") if op not in covered.get(q, set())]
            if not missing:
                continue
            self._add("RLS-020", q, discr=("uncovered",), severity="Informational",
                      rationale="Coverage gap: the boundary for these operations is unverified. This is not a vulnerability by itself.",
                      cls="INCONCLUSIVE", prov=["USER_EXPECTATION"], conf="ASSUMED",
                      summary=f"No expectation covers {', '.join(missing)} on {q}.",
                      evidence=[EvidenceRef(kind="spec", ref=q, summary="no expectation", provenance="USER_EXPECTATION")],
                      objects={"table": q, "operations": missing},
                      remediation="Add ALLOW and DENY expectations (own tenant / other tenant) for the missing operations.")

    # =============================================================== runtime rules
    def run_runtime(self) -> None:
        if not self.run:
            return
        not_exec = [c for c in self.run.cases if c.status in ("ERROR", "UNSUPPORTED", "SKIPPED")]
        for c in self.run.cases:
            if c.status == "FAIL":
                self._runtime_failure(c)
            elif c.status == "INCONCLUSIVE":
                self._runtime_inconclusive(c)
        if not_exec:
            self._add("RLS-020", "run:not-executed", discr=(self.run.info.run_id,), severity="Informational",
                      rationale="Cases that did not execute provide no assurance.", cls="INCONCLUSIVE", prov=["RUNTIME_OBSERVATION"], conf="OBSERVED",
                      summary=f"{len(not_exec)} expectation(s) were not executed ({', '.join(sorted({c.status for c in not_exec}))}).",
                      case_ids=[c.case_id for c in not_exec][:50],
                      evidence=[EvidenceRef(kind="case", ref=c.case_id, summary=c.reason[:140], provenance="RUNTIME_OBSERVATION") for c in not_exec[:10]],
                      verified_by="runtime_lab")

    def _actor(self, c: CaseResult) -> Actor | None:
        return self.spec.actor(c.actor) if self.spec else None

    def rule_for_case(self, c: CaseResult) -> str:
        raw = c.evidence.raw
        a = self._actor(c)
        hint = c.rule_hint
        if c.violation_kind == "authorized_blocked":
            return "RLS-021"
        if c.violation_kind == "policy_error" or hint == "RLS-012":
            return "RLS-012"
        if raw.bypass_reason in ("SUPERUSER", "BYPASSRLS", "TABLE_OWNER"):
            return "RLS-004"
        if raw.bypass_reason == "VIEW_OWNER_BYPASS":
            return "RLS-008"
        if raw.bypass_reason == "FUNCTION_OWNER_BYPASS":
            return "RLS-009"
        if c.violation_kind == "forged_claim_accepted":
            return "RLS-013"
        if hint == "RLS-019":
            return "RLS-013"  # a *confirmed* access with missing identity is a proven identity-handling weakness
        if hint:
            return hint
        if c.violation_kind == "gate_mismatch":
            return "RLS-010"
        if a is not None and a.kind == "anonymous":
            return "RLS-015"
        if c.operation == "SELECT" and c.columns:
            return "RLS-016"
        if c.operation == "INSERT" or (c.operation in ("UPDATE", "UPSERT") and c.moves_tenant):
            return "RLS-005"
        if c.operation in ("SELECT", "EXECUTE"):
            return "RLS-006"
        if a is not None and a.tenant is None and self.spec is not None and self.spec.tenants:
            return "RLS-017"
        return "RLS-007"

    def _runtime_severity(self, c: CaseResult, rule: str) -> tuple[Severity, str]:
        a = self._actor(c)
        if c.violation_kind == "forged_claim_accepted":
            return "Medium", "Policy accepts a forged client-settable value; exploitable only if untrusted clients can run SQL (synthetic test)."
        if c.violation_kind in ("authorized_blocked", "policy_error"):
            return "Medium", "Authorized behaviour is broken (availability/regression); no unauthorized data exposure was observed."
        if c.violation_kind == "gate_mismatch":
            return "Medium", "A privilege the spec says must be absent is granted; access to rows is still denied by RLS."
        if c.operation in WRITE_OPS:
            return "Critical", "Runtime-confirmed unauthorized write across the identity boundary declared in the spec (rolled back in the lab)."
        if a is not None and a.kind == "anonymous":
            return "High", "Runtime-confirmed read by the anonymous identity of data the spec marks private."
        return "High", "Runtime-confirmed read across the identity boundary declared in the spec."

    def _case_evidence(self, c: CaseResult, extra: str = "") -> list[EvidenceRef]:
        raw = c.evidence.raw
        return [
            EvidenceRef(kind="case", ref=c.case_id, provenance="RUNTIME_OBSERVATION",
                        summary=f"{c.operation} as {c.db_role}: expected {c.expected}, observed {c.observed}"
                                f"{f' (SQLSTATE {c.sqlstate})' if c.sqlstate else ''}; rows={raw.row_count}; gate={c.gate}"),
            EvidenceRef(kind="spec", ref=c.case_id, provenance="USER_EXPECTATION",
                        summary=f"independent expectation: {c.expected} for actor {c.actor}" + (f" ({extra})" if extra else "")),
        ]

    def _repro(self, c: CaseResult) -> list[str]:
        fx = self.run.info.fixture if self.run else None
        var = self.run.info.variant if self.run else None
        steps = []
        if fx:
            steps.append(f"rls-sentinel test --fixture {fx} --variant {var} --only {c.case_id}")
        steps.append(f"-- as role {c.db_role} (SET ROLE from a non-superuser login that is a member of it):")
        steps.append(c.evidence.sql or "(sql not recorded)")
        return steps

    def _runtime_failure(self, c: CaseResult) -> None:
        rule = self.rule_for_case(c)
        sev, rationale = self._runtime_severity(c, rule)
        raw = c.evidence.raw
        is_forged = c.violation_kind == "forged_claim_accepted"
        cls: EvidenceClass = "CONFIGURATION_RISK" if (is_forged or c.violation_kind == "gate_mismatch") else "CONFIRMED_VIOLATION"
        lim = "Executed in a disposable database against synthetic fixture data; it demonstrates the behaviour of that schema, not of production."
        if is_forged:
            lim = "SYNTHETIC identity context: proves the policy trusts a settable value, not that the application is exploitable."
        reason = c.reason
        if raw.bypass_reason in ("SUPERUSER", "BYPASSRLS", "TABLE_OWNER"):
            reason += " Root cause: role-level bypass, not a policy expression."
        location = self._case_location(c)
        self._add(
            rule, f"{c.table or ''}#{c.case_id}", discr=(c.case_id,), severity=sev, rationale=rationale, cls=cls,
            prov=["RUNTIME_OBSERVATION", "USER_EXPECTATION"], conf="OBSERVED",
            summary=f"{c.actor} ({c.db_role}) {c.operation} {c.table or ''}"
                    f"{' via ' + c.via if c.via else ''}: {reason}",
            why=RULES[rule].description, expected=c.expected, observed=f"{c.observed}{f' ({c.sqlstate})' if c.sqlstate else ''}, rows={raw.row_count}",
            evidence=self._case_evidence(c), case_ids=[c.case_id],
            objects={"table": c.table, "actor": c.actor, "role": c.db_role, "operation": c.operation, "resource": c.resource,
                     "via": c.via, "applicable_policies": [p.name for p in raw.applicable_policies], "bypass_reason": raw.bypass_reason},
            repro=self._repro(c), limitations=lim, verified_by="runtime_lab", location=location,
        )

    def _case_location(self, c: CaseResult) -> dict | None:
        """Best-effort source location: the permissive policy that granted the access, else the table definition."""
        raw = c.evidence.raw
        names = [p.name for p in raw.applicable_policies if p.permissive] or [p.name for p in raw.applicable_policies]
        for n in names:
            rec = next((p for p in self.snap.policies if p.table == c.table and p.name == n), None)
            if rec is not None and rec.provenance.path:
                return self._loc(rec)
        t = self.snap.table(c.table) if c.table else None
        return self._loc(t) if t is not None else None

    def _runtime_inconclusive(self, c: CaseResult) -> None:
        rule = c.rule_hint or ("RLS-019" if c.evidence.identity_adapter != "postgres_roles" else "RLS-020")
        if rule not in RULES:
            rule = "RLS-020"
        self._add(rule, f"{c.table or ''}#{c.case_id}", discr=(c.case_id, "inconclusive"), severity="Informational",
                  rationale="The case could not decide the authorization outcome; unknown is not safe.",
                  cls="INCONCLUSIVE", prov=["RUNTIME_OBSERVATION"], conf="OBSERVED",
                  summary=f"{c.case_id}: {c.reason}", expected=c.expected, observed=c.observed,
                  evidence=self._case_evidence(c), case_ids=[c.case_id], objects={"table": c.table, "actor": c.actor},
                  verified_by="runtime_lab", limitations="Fix the case data/identity context or declare the intended gate to obtain a decision.")

    # ==================================================================== link + run
    def link_static_to_runtime(self) -> None:
        """Static risks on a table that a runtime case confirmed are linked, so reviewers see the proof."""
        confirmed_by_table: dict[str, list[Finding]] = defaultdict(list)
        for f in self.findings:
            if f.evidence_class == "CONFIRMED_VIOLATION" and f.objects.get("table"):
                confirmed_by_table[f.objects["table"]].append(f)
        for f in self.findings:
            if f.evidence_class == "CONFIGURATION_RISK" and f.objects.get("table") in confirmed_by_table and "RUNTIME_OBSERVATION" not in f.provenance:
                f.related = [x.id for x in confirmed_by_table[f.objects["table"]]][:10]

    def evaluate(self) -> list[Finding]:
        self.findings = []
        self.run_static()
        self.run_runtime()
        self.link_static_to_runtime()
        self.findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.subject))
        return self.findings


def evaluate(snapshot: Snapshot, spec: Spec | None = None, run: RunResult | None = None) -> list[Finding]:
    return RuleEngine(snapshot, spec, run).evaluate()
