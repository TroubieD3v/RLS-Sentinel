import "@xyflow/react/dist/style.css";
import {
  Background, Controls, Handle, MarkerType, MiniMap, Position, ReactFlow, type Edge, type Node, type NodeProps,
} from "@xyflow/react";
import clsx from "clsx";
import {
  Boxes, Database, FileSearch, FlaskConical, FunctionSquare, Layers, ScrollText, ShieldAlert, Table2, UserRound, Users, Eye, Globe, Landmark, User,
} from "lucide-react";
import { memo, useMemo } from "react";
import type { GEdge, GNode, GraphData } from "@/api/types";

const COL_W = 280;
const ROW_H = 74;
const MAX_ROWS = 9; // wrap crowded lanes into several columns so the layout stays compact and deterministic

/** Deterministic lane layout: lanes keep a fixed left-to-right order; a lane with many nodes wraps into extra columns. */
export function layout(nodes: GNode[]): Map<string, { x: number; y: number }> {
  const lanes = new Map<number, GNode[]>();
  for (const n of nodes) lanes.set(n.lane, [...(lanes.get(n.lane) ?? []), n]);
  const pos = new Map<string, { x: number; y: number }>();
  let col = 0;
  for (const lane of [...lanes.keys()].sort((a, b) => a - b)) {
    const list = (lanes.get(lane) ?? []).sort((a, b) => a.order - b.order || a.id.localeCompare(b.id));
    const cols = Math.max(1, Math.ceil(list.length / MAX_ROWS));
    const rows = Math.ceil(list.length / cols);
    list.forEach((n, i) => pos.set(n.id, { x: (col + Math.floor(i / rows)) * COL_W, y: (i % rows) * ROW_H }));
    col += cols;
  }
  return pos;
}

const ICONS: Record<string, typeof Table2> = {
  Database, Schema: Layers, Table: Table2, View: Eye, Function: FunctionSquare, Role: UserRound, RoleGroup: Users, Policy: ScrollText, Tenant: Landmark,
  FixtureIdentity: User, TestCase: FlaskConical, Finding: ShieldAlert, Column: Boxes, Privilege: FileSearch, PUBLIC: Globe,
};

const EDGE_STYLE: Record<GEdge["style"], { stroke: string; dash?: string; width: number; prefix: string }> = {
  catalog: { stroke: "var(--muted)", width: 1.2, prefix: "" },
  static: { stroke: "var(--amber)", dash: "6 5", width: 1.8, prefix: "~ " },
  violation: { stroke: "var(--coral)", width: 2.6, prefix: "✕ " },
  verified: { stroke: "var(--teal)", width: 2, prefix: "✓ " },
};

export interface SentinelNodeData extends Record<string, unknown> {
  g: GNode; dim: boolean; selected: boolean;
}

const SentinelNode = memo(function SentinelNode({ data }: NodeProps<Node<SentinelNodeData>>) {
  const { g, dim, selected } = data;
  const Icon = (g.id === "role:PUBLIC" ? ICONS.PUBLIC : ICONS[g.type]) ?? Table2;
  const p = g.props;
  const badges: { t: string; tone: string }[] = [];
  if (g.type === "Table" || g.type === "View") {
    badges.push(p.rls_enabled ? { t: "RLS", tone: "tone-teal" } : { t: "NO RLS", tone: "tone-amber" });
    if (p.rls_forced) badges.push({ t: "FORCE", tone: "tone-violet" });
    if (g.type === "View") badges.push(p.security_invoker ? { t: "INVOKER", tone: "tone-teal" } : { t: "OWNER-CTX", tone: "tone-amber" });
  }
  if (g.type === "Function" && p.security_definer) badges.push({ t: "DEFINER", tone: "tone-amber" });
  if ((g.type === "Role" || g.type === "RoleGroup") && (p.bypassrls || p.superuser)) badges.push({ t: p.superuser ? "SUPERUSER" : "BYPASSRLS", tone: "tone-coral" });
  if (g.type === "Policy") badges.push({ t: String(p.permissive ? "PERMISSIVE" : "RESTRICTIVE"), tone: p.permissive ? "tone-violet" : "tone-blue" }, { t: String(p.command), tone: "tone-muted" });
  if (g.type === "Finding") badges.push({ t: String(p.severity), tone: p.evidence_class === "CONFIRMED_VIOLATION" ? "tone-coral" : "tone-amber" });
  if (g.type === "TestCase") badges.push({ t: String(p.status), tone: p.status === "FAIL" ? "tone-coral" : p.status === "PASS" ? "tone-teal" : "tone-amber" });
  const shape = g.type === "Role" || g.type === "FixtureIdentity" ? "rounded-full" : g.type === "Policy" ? "rounded-md" : g.type === "Finding" ? "rounded-sm" : "rounded-xl";
  return (
    <div
      className={clsx("t-fast border bg-surface px-2.5 py-1.5 w-[236px] shadow", shape, dim && "opacity-25", selected ? "border-sky ring-2 ring-[var(--blue)]" : "border-line")}
      data-testid={`gnode-${g.id}`}
    >
      <Handle type="target" position={Position.Left} className="!w-1.5 !h-1.5 !bg-[var(--muted)] !border-0" />
      <div className="flex items-center gap-2 min-w-0">
        <Icon size={14} className="shrink-0 text-muted" aria-hidden />
        <span className="font-semibold text-[12px] truncate" title={g.label}>{g.label}</span>
        <span className="ml-auto text-[9px] uppercase tracking-wider text-muted shrink-0">{g.type === "FixtureIdentity" ? "actor" : g.type}</span>
      </div>
      {badges.length > 0 && (
        <div className="flex gap-1 mt-1 flex-wrap">
          {badges.map((b) => <span key={b.t} className={clsx("text-[9px] font-bold tracking-wide border rounded px-1", b.tone)} style={{ borderColor: "currentColor" }}>{b.t}</span>)}
        </div>
      )}
      <Handle type="source" position={Position.Right} className="!w-1.5 !h-1.5 !bg-[var(--muted)] !border-0" />
    </div>
  );
});

const nodeTypes = { sentinel: SentinelNode };

export function neighborhood(edges: GEdge[], focus: string | null, depth = 2): Set<string> | null {
  if (!focus) return null;
  const adj = new Map<string, Set<string>>();
  for (const e of edges) {
    (adj.get(e.source) ?? adj.set(e.source, new Set()).get(e.source)!).add(e.target);
    (adj.get(e.target) ?? adj.set(e.target, new Set()).get(e.target)!).add(e.source);
  }
  const seen = new Set([focus]);
  let frontier = [focus];
  for (let d = 0; d < depth; d++) {
    const next: string[] = [];
    for (const n of frontier) for (const m of adj.get(n) ?? []) if (!seen.has(m)) { seen.add(m); next.push(m); }
    frontier = next;
  }
  return seen;
}

export function GraphCanvas({ data, selectedId, onSelectNode, onSelectEdge, compact = false, height = 560 }: {
  data: GraphData; selectedId: string | null; onSelectNode?: (id: string | null) => void; onSelectEdge?: (e: GEdge) => void; compact?: boolean; height?: number;
}) {
  const near = useMemo(() => neighborhood(data.edges, selectedId), [data.edges, selectedId]);
  const pos = useMemo(() => layout(data.nodes), [data.nodes]);
  const nodes = useMemo<Node<SentinelNodeData>[]>(() => data.nodes.map((g) => ({
    id: g.id, type: "sentinel", position: pos.get(g.id) ?? { x: 0, y: 0 }, draggable: false,
    data: { g, dim: !!near && !near.has(g.id), selected: g.id === selectedId },
  })), [data.nodes, pos, near, selectedId]);
  const edges = useMemo<Edge[]>(() => data.edges.map((e) => {
    const st = EDGE_STYLE[e.style];
    const dim = !!near && !(near.has(e.source) && near.has(e.target));
    return {
      id: e.id, source: e.source, target: e.target, type: "default",
      label: compact ? undefined : `${st.prefix}${e.label || e.type.replaceAll("_", " ").toLowerCase()}`,
      style: { stroke: st.stroke, strokeWidth: st.width, strokeDasharray: st.dash, opacity: dim ? 0.12 : 1 },
      labelStyle: { fontSize: 10, fill: "var(--text)" }, labelBgPadding: [4, 2], labelBgBorderRadius: 4,
      markerEnd: { type: MarkerType.ArrowClosed, color: st.stroke, width: 14, height: 14 },
      animated: false, data: { edge: e } as Record<string, unknown>, ariaLabel: `${e.type} from ${e.source} to ${e.target}: ${e.explanation}`,
    } satisfies Edge;
  }), [data.edges, near, compact]);

  return (
    <div style={{ height }} className="card-flat overflow-hidden" data-testid="graph-canvas" role="application" aria-label="Access graph canvas. A table alternative is available below.">
      <ReactFlow
        nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.12 }} minZoom={0.15} maxZoom={1.8}
        nodesDraggable={false} nodesConnectable={false} elementsSelectable panOnScroll={false} zoomOnScroll={!compact} panOnDrag={!compact}
        onlyRenderVisibleElements={data.nodes.length > 150} proOptions={{ hideAttribution: true }}
        onNodeClick={(_, n) => onSelectNode?.(n.id === selectedId ? null : n.id)}
        onEdgeClick={(_, e) => onSelectEdge?.((e.data as { edge: GEdge }).edge)}
        onPaneClick={() => onSelectNode?.(null)}
      >
        <Background gap={24} size={1} color="var(--border)" />
        {!compact && <Controls showInteractive={false} aria-label="Graph zoom controls" />}
        {!compact && <MiniMap pannable zoomable ariaLabel="Graph minimap" nodeColor={() => "var(--muted)"} maskColor="rgba(0,0,0,.35)" />}
      </ReactFlow>
    </div>
  );
}

export function GraphLegend() {
  const items: { style: GEdge["style"]; text: string }[] = [
    { style: "catalog", text: "Catalog fact" }, { style: "static", text: "Statically inferred" },
    { style: "violation", text: "Runtime-confirmed violation" }, { style: "verified", text: "Expected & verified permitted" },
  ];
  return (
    <ul className="flex flex-wrap gap-x-5 gap-y-1 text-xs text-muted" aria-label="Edge legend">
      {items.map(({ style, text }) => {
        const s = EDGE_STYLE[style];
        return (
          <li key={style} className="inline-flex items-center gap-2">
            <svg width="38" height="8" aria-hidden><line x1="1" y1="4" x2="37" y2="4" stroke={s.stroke} strokeWidth={s.width} strokeDasharray={s.dash} /></svg>
            <span><b className="text-ink">{s.prefix.trim() || "·"}</b> {text}</span>
          </li>
        );
      })}
    </ul>
  );
}
