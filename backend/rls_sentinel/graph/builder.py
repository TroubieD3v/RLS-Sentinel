"""Typed access graph: roles, grants, policies, resources, tests and findings with per-edge evidence."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from ..catalog.models import Snapshot
from ..expectations.models import Spec
from ..findings.models import Finding
from ..harness.results import RunResult
from .roles import RoleGraph

NodeType = Literal["Database", "Schema", "Table", "Column", "View", "Function", "Role", "RoleGroup", "Policy", "Tenant",
                   "FixtureIdentity", "Privilege", "TestCase", "Finding"]
EdgeType = Literal["OWNS", "MEMBER_OF", "INHERITS", "CAN_SET_ROLE", "GRANTS_SELECT", "GRANTS_INSERT", "GRANTS_UPDATE",
                   "GRANTS_DELETE", "GRANTS_EXECUTE", "GRANTS_OTHER", "POLICY_APPLIES_TO", "POLICY_TARGETS_ROLE",
                   "VIEW_REFERENCES", "FUNCTION_REFERENCES", "ROLE_BYPASSES_RLS", "TEST_EXPECTS", "TEST_OBSERVED", "RISK_PATH"]
Style = Literal["catalog", "static", "violation", "verified"]

LANES = {"Role": 0, "RoleGroup": 0, "FixtureIdentity": 0, "Tenant": 0, "Policy": 1, "Table": 2, "View": 2, "Database": 2,
         "Schema": 2, "Function": 3, "Column": 3, "Privilege": 3, "TestCase": 4, "Finding": 4}


class GNode(BaseModel):
    id: str
    type: NodeType
    label: str
    lane: int
    order: int = 0
    props: dict[str, Any] = Field(default_factory=dict)
    source: str | None = None
    evidence_type: str = "CATALOG_FACT"


class GEdge(BaseModel):
    id: str
    source: str
    target: str
    type: EdgeType
    label: str = ""
    style: Style = "catalog"
    evidence_type: Literal["CATALOG_FACT", "STATIC_INFERENCE", "RUNTIME_OBSERVATION", "USER_EXPECTATION"] = "CATALOG_FACT"
    confidence: Literal["ESTABLISHED", "CONDITIONAL", "OBSERVED", "ASSUMED"] = "ESTABLISHED"
    explanation: str = ""
    required_conditions: list[str] = Field(default_factory=list)
    source_ref: str | None = None


class Graph(BaseModel):
    nodes: list[GNode]
    edges: list[GEdge]
    truncated: bool = False
    omitted: dict[str, int] = Field(default_factory=dict)
    totals: dict[str, int] = Field(default_factory=dict)
    cycles: list[list[str]] = Field(default_factory=list)
    legend: dict[str, str] = Field(default_factory=lambda: {
        "catalog": "Catalog fact (solid grey-blue)",
        "static": "Static inference (dashed amber)",
        "violation": "Runtime-confirmed violation (solid coral)",
        "verified": "Expected and verified permitted access (solid teal)",
    })


_GRANT_EDGE = {"SELECT": "GRANTS_SELECT", "INSERT": "GRANTS_INSERT", "UPDATE": "GRANTS_UPDATE", "DELETE": "GRANTS_DELETE"}


class GraphBuilder:
    def __init__(self, snap: Snapshot, spec: Spec | None = None, run: RunResult | None = None,
                 findings: list[Finding] | None = None, *, include_columns: bool = False):
        self.snap, self.spec, self.run, self.findings = snap, spec, run, findings or []
        self.rg = RoleGraph(snap)
        self.nodes: dict[str, GNode] = {}
        self.edges: dict[str, GEdge] = {}
        self.include_columns = include_columns

    # -------------------------------------------------------------- primitives
    def node(self, nid: str, ntype: NodeType, label: str, **props: Any) -> str:
        if nid not in self.nodes:
            self.nodes[nid] = GNode(id=nid, type=ntype, label=label, lane=LANES[ntype], props=props,
                                    source=props.pop("source", None))
        return nid

    def edge(self, src: str, dst: str, etype: EdgeType, **kw: Any) -> None:
        eid = f"{etype}:{src}->{dst}" + (f":{kw['label']}" if kw.get("label") and etype in ("GRANTS_OTHER", "TEST_OBSERVED", "TEST_EXPECTS") else "")
        if eid in self.edges:
            return
        if src in self.nodes and dst in self.nodes:
            self.edges[eid] = GEdge(id=eid, source=src, target=dst, type=etype, **kw)

    # ------------------------------------------------------------------- build
    def build(self) -> Graph:
        snap = self.snap
        db = self.node(f"db:{snap.database}", "Database", snap.database, postgres=snap.postgres_version)
        for s in snap.schemas:
            sid = self.node(f"schema:{s.name}", "Schema", s.name, owner=s.owner, source=s.provenance.ref)
            self.edge(db, sid, "OWNS", label="contains", explanation="schema belongs to database")
        # roles
        groups = {m.role for m in snap.memberships}
        for r in snap.roles:
            if r.system and r.name not in groups and not any(m.member == r.name for m in snap.memberships):
                continue
            ntype: NodeType = "RoleGroup" if (r.name in groups and not r.login) else "Role"
            self.node(f"role:{r.name}", ntype, r.name, login=r.login, superuser=r.superuser, bypassrls=r.bypassrls,
                      system=r.system, source=r.provenance.ref)
        self.node("role:PUBLIC", "RoleGroup", "PUBLIC", pseudo=True)
        # relations
        for t in snap.tables:
            if t.extension_owned:
                continue
            nt: NodeType = "View" if t.is_view else "Table"
            tid = self.node(f"table:{t.qualified}", nt, t.qualified, rls_enabled=t.rls_enabled, rls_forced=t.rls_forced,
                            owner=t.owner, security_invoker=t.security_invoker, kind=t.kind,
                            protected=t.qualified in self._protected(), source=t.provenance.ref,
                            path=t.provenance.path, line=t.provenance.line)
            sid = f"schema:{t.schema_name}"
            if sid in self.nodes:
                self.edge(sid, tid, "OWNS", label="contains")
            if f"role:{t.owner}" in self.nodes:
                self.edge(f"role:{t.owner}", tid, "OWNS", explanation=f"{t.owner} owns {t.qualified}", source_ref=t.provenance.ref)
            for b in t.view_depends_on:
                self.node(f"table:{b}", "Table", b)
                self.edge(tid, f"table:{b}", "VIEW_REFERENCES", label="reads",
                          explanation=f"{t.qualified} reads {b} " + ("with the caller's privileges (security_invoker)" if t.security_invoker else "with its owner's privileges"),
                          source_ref=t.provenance.ref)
            if self.include_columns:
                for c in t.columns:
                    cid = self.node(f"col:{t.qualified}.{c.name}", "Column", f"{t.name}.{c.name}", type=c.type)
                    self.edge(tid, cid, "OWNS", label="column")
        for fn in snap.functions:
            if fn.extension_owned:
                continue
            fid = self.node(f"function:{fn.qualified}", "Function", f"{fn.name}({fn.identity_args})", security_definer=fn.security_definer,
                            owner=fn.owner, search_path_pinned=fn.has_fixed_search_path, public_execute=fn.public_execute, source=fn.provenance.ref,
                            path=fn.provenance.path, line=fn.provenance.line)
            if f"role:{fn.owner}" in self.nodes:
                self.edge(f"role:{fn.owner}", fid, "OWNS", explanation=f"{fn.owner} owns the function")
        # memberships
        for m in snap.memberships:
            a, b = f"role:{m.member}", f"role:{m.role}"
            if a in self.nodes and b in self.nodes:
                inherit = m.inherit_option if m.inherit_option is not None else bool(self.rg.roles.get(m.member) and self.rg.roles[m.member].inherit)
                self.edge(a, b, "MEMBER_OF", explanation=f"{m.member} is a member of {m.role}"
                          + (" (inherits its privileges)" if inherit else " (does NOT inherit privileges; may only SET ROLE)"),
                          source_ref="pg_auth_members")
                if inherit:
                    self.edge(a, b, "INHERITS", label="inherits", explanation=f"{m.member} automatically uses privileges of {m.role}", source_ref="pg_auth_members")
                if m.set_option is not False:
                    self.edge(a, b, "CAN_SET_ROLE", label="SET ROLE", explanation=f"{m.member} may SET ROLE {m.role}", source_ref="pg_auth_members")
        # grants
        for g in snap.grants:
            if g.object_type != "table":
                if g.object_type == "function":
                    self._grant_edge(g.grantee, f"function:{g.object}", "GRANTS_EXECUTE", "EXECUTE", g.provenance.ref)
                continue
            et = _GRANT_EDGE.get(g.privilege)
            if et is None:
                self._grant_edge(g.grantee, f"table:{g.object}", "GRANTS_OTHER", g.privilege, g.provenance.ref)
            else:
                self._grant_edge(g.grantee, f"table:{g.object}", et, g.privilege, g.provenance.ref)  # type: ignore[arg-type]
        # policies
        for p in snap.policies:
            pid = self.node(f"policy:{p.table}:{p.name}", "Policy", p.name, command=p.command, permissive=p.permissive,
                            using=p.using_expr, check=p.check_expr, roles=p.roles, source=p.provenance.ref,
                            path=p.provenance.path, line=p.provenance.line)
            self.edge(pid, f"table:{p.table}", "POLICY_APPLIES_TO", label=f"{'PERMISSIVE' if p.permissive else 'RESTRICTIVE'} {p.command}",
                      explanation=f"{'Permissive' if p.permissive else 'Restrictive'} {p.command} policy on {p.table}", source_ref=p.provenance.ref)
            for rname in p.roles:
                self.edge(pid, f"role:{rname}", "POLICY_TARGETS_ROLE", explanation=f"Policy applies to {rname}", source_ref=p.provenance.ref)
            for fname in p.deps.functions:
                if f"function:{fname}" in self.nodes:
                    self.edge(pid, f"function:{fname}", "FUNCTION_REFERENCES", label="calls", explanation="policy expression calls function", source_ref=p.provenance.ref)
        # bypass
        for r in snap.roles:
            if r.system or not (r.superuser or r.bypassrls):
                continue
            for t in snap.tables:
                if t.rls_enabled and f"table:{t.qualified}" in self.nodes and f"role:{r.name}" in self.nodes and t.qualified in self._protected():
                    self.edge(f"role:{r.name}", f"table:{t.qualified}", "ROLE_BYPASSES_RLS", label="BYPASSRLS" if r.bypassrls else "SUPERUSER",
                              explanation=f"{r.name} ignores row-level security", source_ref=r.provenance.ref)
        for t in snap.tables:
            if t.rls_enabled and not t.rls_forced and t.kind in ("table", "partitioned_table") and t.qualified in self._protected() and f"role:{t.owner}" in self.nodes:
                self.edge(f"role:{t.owner}", f"table:{t.qualified}", "ROLE_BYPASSES_RLS", label="OWNER (no FORCE)", style="static",
                          evidence_type="STATIC_INFERENCE", confidence="CONDITIONAL",
                          explanation=f"{t.owner} owns the table and FORCE ROW LEVEL SECURITY is off",
                          required_conditions=[f"sessions connect as {t.owner} or a role that inherits it"], source_ref=t.provenance.ref)
        self._spec_and_runtime()
        self._findings()
        return self._finish()

    def _protected(self) -> set[str]:
        if self.spec:
            return {tc.table for tc in self.spec.tables if tc.protected} | {r.table for r in self.spec.resources}
        return {t.qualified for t in self.snap.tables if any(c.tenant_candidate for c in t.columns)}

    def _grant_edge(self, grantee: str, target: str, etype: EdgeType, priv: str, ref: str | None) -> None:
        src = f"role:{grantee}"
        if src not in self.nodes or target not in self.nodes:
            return
        self.edge(src, target, etype, label=priv, explanation=f"{grantee} holds {priv} (ACL entry)", source_ref=ref)

    # ----------------------------------------------------- spec + runtime layers
    def _spec_and_runtime(self) -> None:
        if not self.spec:
            return
        for t in self.spec.tenants:
            self.node(f"tenant:{t.id}", "Tenant", t.name or t.id)
        for a in self.spec.actors:
            aid = self.node(f"actor:{a.id}", "FixtureIdentity", a.id, pg_role=a.pg_role, tenant=a.tenant, kind=a.kind,
                            expect_bypass=a.expect_bypass)
            if a.tenant and f"tenant:{a.tenant}" in self.nodes:
                self.edge(aid, f"tenant:{a.tenant}", "TEST_EXPECTS", label="belongs to", evidence_type="USER_EXPECTATION",
                          confidence="ASSUMED", explanation=f"{a.id} belongs to tenant {a.tenant} (spec)")
            if f"role:{a.pg_role}" in self.nodes:
                self.edge(aid, f"role:{a.pg_role}", "CAN_SET_ROLE", label="acts as", evidence_type="USER_EXPECTATION", confidence="ASSUMED",
                          explanation=f"actor {a.id} is exercised through database role {a.pg_role}")
        if not self.run:
            for e in self.spec.expectations:
                res = self.spec.resource(e.resource) if e.resource else None
                tbl = e.table or (res.table if res else None)
                if tbl and f"table:{tbl}" in self.nodes and f"actor:{e.actor}" in self.nodes:
                    self.edge(f"actor:{e.actor}", f"table:{tbl}", "TEST_EXPECTS", label=f"{e.operation} {e.expected}", evidence_type="USER_EXPECTATION",
                              confidence="ASSUMED", style="static", explanation=e.description or f"{e.actor} expected {e.expected} for {e.operation} (not yet executed)")
            return
        for c in self.run.cases:
            cid = self.node(f"case:{c.case_id}", "TestCase", c.case_id, status=c.status, expected=c.expected, observed=c.observed,
                            operation=c.operation, actor=c.actor, table=c.table)
            if f"actor:{c.actor}" in self.nodes:
                self.edge(f"actor:{c.actor}", cid, "TEST_EXPECTS", label=f"{c.operation} {c.expected}", evidence_type="USER_EXPECTATION",
                          confidence="ASSUMED", explanation=c.description or f"expected {c.expected}")
            if c.table and f"table:{c.table}" in self.nodes:
                self.edge(cid, f"table:{c.table}", "TEST_OBSERVED", label=c.observed, evidence_type="RUNTIME_OBSERVATION", confidence="OBSERVED",
                          style="violation" if c.status == "FAIL" else ("verified" if c.status == "PASS" and c.expected == "ALLOW" else "catalog"),
                          explanation=c.reason, source_ref=c.case_id)
            if c.status == "FAIL" and c.violation_kind == "unauthorized_access" and c.table and f"table:{c.table}" in self.nodes and f"actor:{c.actor}" in self.nodes:
                self.edge(f"actor:{c.actor}", f"table:{c.table}", "RISK_PATH", label=f"{c.operation} (confirmed)", style="violation",
                          evidence_type="RUNTIME_OBSERVATION", confidence="OBSERVED",
                          explanation=c.reason, source_ref=c.case_id)
            elif c.status == "PASS" and c.expected == "ALLOW" and c.table and f"table:{c.table}" in self.nodes and f"actor:{c.actor}" in self.nodes:
                self.edge(f"actor:{c.actor}", f"table:{c.table}", "RISK_PATH", label=f"{c.operation} (verified)", style="verified",
                          evidence_type="RUNTIME_OBSERVATION", confidence="OBSERVED", explanation=f"{c.actor} may {c.operation}: {c.reason}", source_ref=c.case_id)

    def _findings(self) -> None:
        for f in self.findings:
            fid = self.node(f"finding:{f.id}", "Finding", f.rule_id, severity=f.severity, evidence_class=f.evidence_class, summary=f.summary)
            obj = f.objects
            targets = []
            for key in ("table", "view", "base"):
                if obj.get(key):
                    targets.append(f"table:{obj[key]}")
            if obj.get("function"):
                targets.append(f"function:{obj['function']}")
            if obj.get("policy") and obj.get("table"):
                targets.append(f"policy:{obj['table']}:{obj['policy']}")
            if obj.get("role"):
                targets.append(f"role:{obj['role']}")
            confirmed = f.evidence_class == "CONFIRMED_VIOLATION"
            for t in dict.fromkeys(targets):
                if t in self.nodes:
                    self.edge(fid, t, "RISK_PATH", label=f.rule_id, style="violation" if confirmed else "static",
                              evidence_type="RUNTIME_OBSERVATION" if confirmed else "STATIC_INFERENCE",
                              confidence="OBSERVED" if confirmed else "CONDITIONAL", explanation=f.summary, source_ref=f.id)

    # ----------------------------------------------------------------- finish
    def _finish(self) -> Graph:
        order: dict[int, int] = {}
        for n in sorted(self.nodes.values(), key=lambda n: (n.lane, n.type, n.label)):
            n.order = order.get(n.lane, 0)
            order[n.lane] = n.order + 1
        return Graph(nodes=list(self.nodes.values()), edges=list(self.edges.values()),
                     totals={"nodes": len(self.nodes), "edges": len(self.edges)}, cycles=self.rg.cycles)


def build_graph(snap: Snapshot, spec: Spec | None = None, run: RunResult | None = None, findings: list[Finding] | None = None,
                *, include_columns: bool = False) -> Graph:
    return GraphBuilder(snap, spec, run, findings, include_columns=include_columns).build()


def subgraph(g: Graph, *, focus: list[str] | None = None, depth: int = 2, max_nodes: int = 400, max_edges: int = 1200,
             hide_types: set[str] | None = None) -> Graph:
    """Focused / capped view. Never silently drops data: ``truncated`` and ``omitted`` are set explicitly."""
    keep: set[str] = set()
    adj: dict[str, set[str]] = {}
    types = {n.id: n.type for n in g.nodes}
    for e in g.edges:
        # hidden node types are neither shown nor traversed (otherwise a hub such as PUBLIC pulls in the whole graph)
        if hide_types and (types.get(e.source) in hide_types or types.get(e.target) in hide_types):
            continue
        adj.setdefault(e.source, set()).add(e.target)
        adj.setdefault(e.target, set()).add(e.source)
    if focus:
        frontier = {f for f in focus if f in {n.id for n in g.nodes}}
        keep |= frontier
        for _ in range(depth):
            nxt: set[str] = set()
            for n in frontier:
                nxt |= adj.get(n, set())
            frontier = nxt - keep
            keep |= nxt
    else:
        keep = {n.id for n in g.nodes}
    if hide_types:
        types = {n.id: n.type for n in g.nodes}
        keep = {k for k in keep if types.get(k) not in hide_types}
    deg = {n: len(adj.get(n, ())) for n in keep}
    nodes = [n for n in g.nodes if n.id in keep]
    omitted_nodes = 0
    if len(nodes) > max_nodes:
        prio = {"Finding": 0, "Table": 1, "View": 1, "Policy": 2, "Role": 3, "RoleGroup": 3, "FixtureIdentity": 3, "Function": 4}
        focus_set = set(focus or [])
        nodes.sort(key=lambda n: (0 if n.id in focus_set else 1, prio.get(n.type, 5), -deg.get(n.id, 0), n.id))
        omitted_nodes = len(nodes) - max_nodes
        nodes = nodes[:max_nodes]
    ids = {n.id for n in nodes}
    edges = [e for e in g.edges if e.source in ids and e.target in ids]
    omitted_edges = 0
    if len(edges) > max_edges:
        pr = {"violation": 0, "static": 1, "verified": 2, "catalog": 3}
        edges.sort(key=lambda e: (pr[e.style], e.id))
        omitted_edges = len(edges) - max_edges
        edges = edges[:max_edges]
    truncated = bool(omitted_nodes or omitted_edges)
    return Graph(nodes=nodes, edges=edges, truncated=truncated, omitted={"nodes": omitted_nodes, "edges": omitted_edges},
                 totals=g.totals, cycles=g.cycles, legend=g.legend)


def access_paths(snap: Snapshot, role: str, table: str | None = None) -> list[dict[str, Any]]:
    """Explain how ``role`` reaches each table: membership chain, granting role, SQL privilege and RLS outcome."""
    rg = RoleGraph(snap)
    out: list[dict[str, Any]] = []
    closure = rg.inherit_closure(role)
    for t in snap.tables:
        if table and t.qualified != table:
            continue
        if t.extension_owned:
            continue
        privs: dict[str, list[dict[str, Any]]] = {}
        for g in snap.grants:
            if g.object_type == "table" and g.object == t.qualified and (g.grantee in closure or g.grantee == "PUBLIC"):
                privs.setdefault(g.privilege, []).append({"granted_to": g.grantee, "via_membership": g.grantee != role and g.grantee != "PUBLIC",
                                                         "source": g.provenance.ref})
        owner_path = t.owner in closure
        bypass = rg.bypasses_rls(role, t.qualified)
        if not privs and not owner_path and not bypass:
            continue
        policies = [{"name": p.name, "command": p.command, "permissive": p.permissive, "roles": p.roles}
                    for p in snap.policies_for(t.qualified) if rg.applicable_roles(p.roles) & {role} or "PUBLIC" in p.roles
                    or any(r in closure for r in p.roles)]
        if not t.rls_enabled:
            outcome = "RLS disabled: SQL privileges alone decide access"
        elif bypass:
            outcome = f"RLS bypassed ({bypass})"
        elif not any(p["permissive"] for p in policies):
            outcome = "RLS enabled with no applicable permissive policy: default deny"
        else:
            outcome = "RLS applies: row access limited by the listed policies"
        out.append({"table": t.qualified, "role": role, "owner_path": owner_path, "privileges": privs, "policies": policies,
                    "rls_enabled": t.rls_enabled, "rls_forced": t.rls_forced, "bypass": bypass, "outcome": outcome,
                    "evidence_type": "CATALOG_FACT"})
    return out
