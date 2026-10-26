import { useQuery } from "@tanstack/react-query";
import { AlertTriangle } from "lucide-react";
import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "@/api/client";
import type { GEdge, GNode } from "@/api/types";
import { PageHeader } from "@/components/Shell";
import { Button, Card, EmptyState, ErrorState, Lozenge, ProvenanceLozenge, Select, Skeleton } from "@/design-system/ui";
import { GraphCanvas, GraphLegend } from "@/graph/GraphCanvas";
import { useActiveRun, useRunGraph } from "@/lib/queries";

interface AccessPath {
  table: string; role: string; owner_path: boolean; privileges: Record<string, { granted_to: string; via_membership: boolean }[]>;
  policies: { name: string; command: string; permissive: boolean }[]; rls_enabled: boolean; rls_forced: boolean; bypass: string | null; outcome: string;
}
const HIDE_OPTS = ["Schema", "Database", "TestCase", "Finding", "Policy", "FixtureIdentity", "Tenant", "Function"];

function evKind(t: string) {
  return t === "RUNTIME_OBSERVATION" ? "runtime" : t === "STATIC_INFERENCE" ? "static" : t === "USER_EXPECTATION" ? "insufficient" : "catalog";
}

export default function GraphPage() {
  const { run, isLoading, error } = useActiveRun();
  const [sp, setSp] = useSearchParams();
  const role = sp.get("role") ?? "";
  const table = sp.get("table") ?? "";
  const [depth, setDepth] = useState(1);
  const [hide, setHide] = useState<string[]>(["Schema", "Database", "TestCase", "Finding"]);
  const [maxNodes, setMaxNodes] = useState(120);
  const [selNode, setSelNode] = useState<string | null>(null);
  const [selEdge, setSelEdge] = useState<GEdge | null>(null);
  const [tableView, setTableView] = useState(false);
  const g = useRunGraph(run?.id, { role, table, depth, max_nodes: maxNodes, hide: hide.join(",") });
  const full = useRunGraph(run?.id, { max_nodes: 2000, depth: 0 });
  const roles = useMemo(() => (full.data?.nodes ?? []).filter((n) => n.type === "Role" || n.type === "RoleGroup").map((n) => n.label).sort(), [full.data]);
  const tables = useMemo(() => (full.data?.nodes ?? []).filter((n) => n.type === "Table" || n.type === "View").map((n) => n.label).sort(), [full.data]);
  const node: GNode | undefined = g.data?.nodes.find((n) => n.id === selNode);
  const roleForPaths = node && (node.type === "Role" || node.type === "RoleGroup") ? node.label : role;
  const paths = useQuery({
    queryKey: ["paths", run?.snapshot_id, roleForPaths], enabled: !!run?.snapshot_id && !!roleForPaths,
    queryFn: async () => (await api<AccessPath[]>(`/scans/${run!.snapshot_id}/access-paths?role=${encodeURIComponent(roleForPaths)}`)).data,
  });

  if (isLoading) return <Skeleton className="h-96" />;
  if (error) return <ErrorState error={error} />;
  if (!run) return <EmptyState title="No graph yet">Run a verification or scan to build the access graph.</EmptyState>;
  const sg = g.data;
  const edgesOf = (id: string) => (sg?.edges ?? []).filter((e) => e.source === id || e.target === id);
  return (
    <div className="grid gap-4">
      <PageHeader kicker="Database access graph" title="Access graph"
        subtitle="Who can reach which resource, and through which membership, grant, policy, view or function. Every edge carries its provenance; effective SQL permission is separate from the row-policy outcome." />
      <Card>
        <div className="flex flex-wrap gap-3 items-end">
          <label className="grid gap-1 text-xs text-muted">Role-centric<Select aria-label="Focus role" value={role} onChange={(e) => setSp(e.target.value ? { role: e.target.value } : {})} className="w-48"><option value="">— none —</option>{roles.map((r) => <option key={r}>{r}</option>)}</Select></label>
          <label className="grid gap-1 text-xs text-muted">Table-centric<Select aria-label="Focus table" value={table} onChange={(e) => setSp(e.target.value ? { table: e.target.value } : {})} className="w-56"><option value="">— none —</option>{tables.map((r) => <option key={r}>{r}</option>)}</Select></label>
          <label className="grid gap-1 text-xs text-muted">Depth<Select aria-label="Depth" value={depth} onChange={(e) => setDepth(Number(e.target.value))} className="w-20">{[1, 2, 3, 4].map((d) => <option key={d}>{d}</option>)}</Select></label>
          <label className="grid gap-1 text-xs text-muted">Node cap<Select aria-label="Node cap" value={maxNodes} onChange={(e) => setMaxNodes(Number(e.target.value))} className="w-24">{[60, 120, 250, 400, 800].map((d) => <option key={d}>{d}</option>)}</Select></label>
          <fieldset className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted items-center"><legend className="sr-only">Hide node types</legend>Hide:
            {HIDE_OPTS.map((h) => <label key={h} className="inline-flex gap-1 items-center"><input type="checkbox" checked={hide.includes(h)} onChange={(e) => setHide(e.target.checked ? [...hide, h] : hide.filter((x) => x !== h))} />{h}</label>)}</fieldset>
          <div className="ml-auto flex gap-2">{(role || table) && <Button size="sm" onClick={() => setSp({})}>Clear focus</Button>}
            <Button size="sm" onClick={() => setTableView((v) => !v)} aria-pressed={tableView}>{tableView ? "Show graph" : "Show table equivalent"}</Button></div>
        </div>
      </Card>
      {sg?.truncated && (
        <div role="status" className="card-flat px-4 py-2.5 flex gap-2 items-center text-[13px]" style={{ borderColor: "var(--amber)" }} data-testid="truncated-banner">
          <AlertTriangle size={16} className="tone-amber" aria-hidden /> <b>truncated=true</b> — showing {sg.nodes.length} of {sg.totals.nodes} nodes; {sg.omitted.nodes} nodes and {sg.omitted.edges} edges omitted. Narrow the focus or raise the cap.
        </div>
      )}
      {sg?.cycles && sg.cycles.length > 0 && <div role="alert" className="card-flat px-4 py-2 text-[13px] tone-amber">Role membership cycle detected: {sg.cycles[0].join(" → ")}</div>}
      <div className="grid xl:grid-cols-[1fr_400px] gap-4 items-start">
        <Card padded>
          {g.isLoading || !sg ? <Skeleton className="h-[560px]" /> : tableView ? (
            <div tabIndex={0} role="region" aria-label="Graph edges table" className="overflow-auto scroll-thin max-h-[620px]" data-testid="graph-table">
              <table className="w-full text-xs"><caption className="sr-only">Graph edges</caption>
                <thead><tr className="text-left text-muted"><th className="p-1.5">From</th><th className="p-1.5">Edge</th><th className="p-1.5">To</th><th className="p-1.5">Evidence</th><th className="p-1.5">Why</th></tr></thead>
                <tbody>{sg.edges.map((e) => (
                  <tr key={e.id} className="border-t border-line align-top"><td className="p-1.5 mono">{e.source}</td><td className="p-1.5 mono font-bold">{e.type}{e.label ? ` (${e.label})` : ""}</td><td className="p-1.5 mono">{e.target}</td>
                    <td className="p-1.5"><ProvenanceLozenge kind={evKind(e.evidence_type)} /> {e.style === "violation" ? "✕ confirmed" : e.style === "verified" ? "✓ verified" : e.style === "static" ? "~ inferred" : ""}</td><td className="p-1.5">{e.explanation}</td></tr>))}</tbody></table>
            </div>
          ) : <>
            <GraphCanvas data={sg} selectedId={selNode} onSelectNode={(id) => { setSelNode(id); setSelEdge(null); }} onSelectEdge={(e) => setSelEdge(e)} height={600} />
            <div className="mt-3 flex flex-wrap items-center gap-x-6 gap-y-2"><GraphLegend /><span className="text-xs text-muted ml-auto mono">{sg.nodes.length} nodes · {sg.edges.length} edges · lanes: identities | policies | resources | functions | tests & findings</span></div>
          </>}
        </Card>
        <Card title="Inspector" subtitle="Source, effective privilege and whether the relation is runtime-proven or static" padded>
          {selEdge ? (
            <div className="grid gap-2 text-[13px]" data-testid="edge-inspector">
              <div className="flex gap-2 flex-wrap"><ProvenanceLozenge kind={evKind(selEdge.evidence_type)} /><Lozenge tone="muted">{selEdge.confidence}</Lozenge></div>
              <div className="mono font-bold break-all">{selEdge.type}</div><div className="mono text-xs break-all">{selEdge.source} → {selEdge.target}</div>
              <p>{selEdge.explanation}</p>
              {selEdge.required_conditions.length > 0 && <ul className="list-disc pl-4 text-xs text-muted">{selEdge.required_conditions.map((c) => <li key={c}>{c}</li>)}</ul>}
              <p className="text-xs text-muted mono">source: {selEdge.source_ref ?? "—"}</p>
            </div>
          ) : node ? (
            <div className="grid gap-2 text-[13px]" data-testid="node-inspector">
              <div className="flex gap-2 flex-wrap items-center"><Lozenge tone="violet">{node.type}</Lozenge><b className="mono break-all">{node.label}</b></div>
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">{Object.entries(node.props).filter(([, v]) => v !== null && v !== undefined && typeof v !== "object").slice(0, 12).map(([k, v]) => (<><dt key={`${k}d`} className="text-muted">{k}</dt><dd key={`${k}v`} className="mono break-all">{String(v)}</dd></>))}</dl>
              <p className="text-xs text-muted mono">catalog source: {node.source ?? "—"}</p>
              <div className="text-xs font-bold uppercase tracking-wide text-muted mt-1">Relations ({edgesOf(node.id).length})</div>
              <ul className="grid gap-1 max-h-48 overflow-auto scroll-thin">{edgesOf(node.id).map((e) => <li key={e.id}><button type="button" className="text-left text-xs hover:underline mono" onClick={() => setSelEdge(e)}>{e.style === "violation" ? "✕" : e.style === "verified" ? "✓" : e.style === "static" ? "~" : "·"} {e.type} {e.source === node.id ? "→ " + e.target : "← " + e.source}</button></li>)}</ul>
            </div>
          ) : <p className="text-[13px] text-muted">Select a node or an edge. Unrelated nodes dim so the selected access path stands out.</p>}
          {roleForPaths && (
            <div className="mt-4 grid gap-2" data-testid="access-paths">
              <div className="text-xs font-bold uppercase tracking-wide text-muted">Access paths for <span className="mono">{roleForPaths}</span></div>
              {paths.isLoading && <Skeleton className="h-16" />}
              {paths.data?.length === 0 && <p className="text-xs text-muted">No reachable tables via SQL privileges.</p>}
              <ul tabIndex={0} aria-label="Access paths" className="grid gap-1.5 max-h-72 overflow-auto scroll-thin">{(paths.data ?? []).map((p) => (
                <li key={p.table} className="card-flat p-2 text-xs"><div className="mono font-bold">{p.table}</div>
                  <div className="text-muted">{Object.entries(p.privileges).map(([k, v]) => `${k}${v.some((x) => x.via_membership) ? " (via membership)" : ""}`).join(", ") || (p.owner_path ? "owner" : "")}</div>
                  <div className={p.bypass ? "tone-coral font-semibold" : ""}>{p.outcome}</div></li>))}</ul>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
