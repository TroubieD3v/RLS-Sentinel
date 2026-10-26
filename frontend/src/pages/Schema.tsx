import clsx from "clsx";
import { ChevronDown, ChevronRight, Database, Eye, FunctionSquare, Layers, Table2 } from "lucide-react";
import { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import type { Snapshot, TableRec } from "@/api/types";
import { PageHeader } from "@/components/Shell";
import { Card, EmptyState, ErrorState, Input, Lozenge, ProvenanceLozenge, Skeleton } from "@/design-system/ui";
import { useActiveRun, useSnapshot } from "@/lib/queries";
import { Sql, SqlBlock } from "@/lib/sql";

const q = (t: TableRec) => `${t.schema}.${t.name}`;

function Badges({ t }: { t: TableRec }) {
  const view = t.kind === "view" || t.kind === "materialized_view";
  return (
    <span className="inline-flex gap-1 flex-wrap">
      {!view && (t.rls_enabled ? <Lozenge tone="teal">RLS</Lozenge> : <Lozenge tone="amber">No RLS</Lozenge>)}
      {t.rls_forced && <Lozenge tone="violet">Force</Lozenge>}
      {view && (t.options.security_invoker === "true" || t.options.security_invoker === true ? <Lozenge tone="teal">Invoker</Lozenge> : <Lozenge tone="amber">Owner ctx</Lozenge>)}
    </span>
  );
}

function Detail({ snap, t }: { snap: Snapshot; t: TableRec }) {
  const key = q(t);
  const policies = snap.policies.filter((p) => p.table === key);
  const grants = snap.grants.filter((g) => g.object === key && g.object_type === "table");
  const colGrants = snap.grants.filter((g) => g.object_type === "column" && g.object.startsWith(`${key}.`));
  const view = t.kind === "view" || t.kind === "materialized_view";
  const readers = Array.from(new Set(grants.filter((g) => g.privilege === "SELECT").map((g) => g.grantee)));
  return (
    <div className="grid gap-4" data-testid="table-detail">
      <div className="flex items-center gap-2 flex-wrap"><h2 className="text-lg font-bold mono break-all">{key}</h2><Badges t={t} /><ProvenanceLozenge kind="catalog" /></div>
      <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1 text-[13px]">
        <dt className="text-muted">Kind</dt><dd>{t.kind.replace("_", " ")}</dd>
        <dt className="text-muted">Owner</dt><dd className="mono">{t.owner}</dd>
        <dt className="text-muted">Row-level security</dt><dd>{t.rls_enabled ? "enabled" : "disabled"}{t.rls_forced ? " · FORCE (owner subject to policies)" : t.rls_enabled ? " · owner bypasses (no FORCE)" : ""}</dd>
        <dt className="text-muted">Estimated rows</dt><dd className="mono">{t.row_estimate ?? "unknown"} <span className="text-muted">(planner estimate; no row data read)</span></dd>
        {t.primary_key.length > 0 && <><dt className="text-muted">Primary key</dt><dd className="mono">{t.primary_key.join(", ")}</dd></>}
        {view && <><dt className="text-muted">Reads</dt><dd className="mono">{t.view_depends_on.join(", ") || "—"}</dd></>}
        {view && <><dt className="text-muted">Who can SELECT</dt><dd className="mono">{readers.join(", ") || "no explicit grants"}</dd></>}
        {t.provenance.path && <><dt className="text-muted">Source</dt><dd className="mono">{t.provenance.path}:{t.provenance.line}</dd></>}
      </dl>
      {!t.rls_enabled && !view && policies.length > 0 && <p className="card-flat p-3 text-[13px] tone-amber">Policies exist but are inactive because RLS is disabled on this table.</p>}
      {t.rls_enabled && policies.length === 0 && !view && <p className="card-flat p-3 text-[13px]">RLS is enabled with no policies: ordinary roles are denied by default (this is not an open table).</p>}
      <section aria-label="Policies"><h3 className="text-xs font-bold uppercase tracking-wide text-muted mb-1">Policies ({policies.length})</h3>
        <ul className="grid gap-2">{policies.map((p) => (
          <li key={p.name} className="card-flat p-3 grid gap-1.5">
            <div className="flex gap-2 items-center flex-wrap"><span className="mono font-bold">{p.name}</span><Lozenge tone={p.permissive ? "violet" : "blue"}>{p.permissive ? "permissive" : "restrictive"}</Lozenge><Lozenge tone="muted">{p.command}</Lozenge>
              {p.roles.map((r) => <span key={r} className="mono text-xs border border-line rounded px-1.5">{r}</span>)}</div>
            <div className="text-xs text-muted">USING</div><Sql text={p.using_expr} />
            <div className="text-xs text-muted">WITH CHECK</div><Sql text={p.check_expr} />
          </li>))}</ul></section>
      <section aria-label="Columns"><h3 className="text-xs font-bold uppercase tracking-wide text-muted mb-1">Columns ({t.columns.length})</h3>
        <div className="card-flat overflow-auto scroll-thin"><table className="w-full text-[12px]"><thead><tr className="text-left text-muted"><th className="p-2">#</th><th className="p-2">Name</th><th className="p-2">Type</th><th className="p-2">Null</th><th className="p-2">Column-level grants</th></tr></thead>
          <tbody>{t.columns.map((c) => (
            <tr key={c.name} className="border-t border-line"><td className="p-2 text-muted">{c.position}</td>
              <td className="p-2 mono font-semibold">{c.name}{c.tenant_candidate && <Lozenge tone="blue">tenant-like</Lozenge>}</td><td className="p-2 mono">{c.type}</td><td className="p-2">{c.not_null ? "NOT NULL" : "null"}</td>
              <td className="p-2 mono">{colGrants.filter((g) => g.object === `${key}.${c.name}`).map((g) => `${g.grantee}:${g.privilege}`).join(", ") || "—"}</td></tr>))}</tbody></table></div></section>
      <section aria-label="Table grants"><h3 className="text-xs font-bold uppercase tracking-wide text-muted mb-1">Table-level privileges</h3>
        {grants.length === 0 ? <p className="text-[13px] text-muted">No explicit ACL entries{t.owner ? ` (owner ${t.owner} has default privileges)` : ""}.</p> : (
          <ul className="flex flex-wrap gap-1.5">{grants.map((g, i) => <li key={i} className="mono text-xs card-flat px-2 py-1">{g.grantee} · <b>{g.privilege}</b></li>)}</ul>)}</section>
      {view && t.view_definition && <section aria-label="View definition"><h3 className="text-xs font-bold uppercase tracking-wide text-muted mb-1">View definition</h3><SqlBlock text={t.view_definition} /></section>}
    </div>
  );
}

export default function SchemaExplorer() {
  const { run, isLoading, error } = useActiveRun();
  const snap = useSnapshot(run?.snapshot_id);
  const [sp, setSp] = useSearchParams();
  const [filter, setFilter] = useState("");
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const sel = sp.get("table");
  const data = snap.data;
  const tables = useMemo(() => (data?.tables ?? []).filter((t) => !t.provenance || true).filter((t) => !filter || q(t).toLowerCase().includes(filter.toLowerCase()) ||
    data?.policies.some((p) => p.table === q(t) && p.name.toLowerCase().includes(filter.toLowerCase()))), [data, filter]);
  const bySchema = useMemo(() => {
    const m = new Map<string, TableRec[]>();
    for (const t of tables) m.set(t.schema, [...(m.get(t.schema) ?? []), t]);
    return m;
  }, [tables]);
  const current = data?.tables.find((t) => q(t) === sel) ?? null;

  if (isLoading || snap.isLoading) return <Skeleton className="h-96" />;
  if (error || snap.error) return <ErrorState error={error ?? snap.error} />;
  if (!run || !data) return <EmptyState title="No catalog snapshot yet">Run a scan or verification to inspect the schema.</EmptyState>;
  return (
    <div className="grid gap-4">
      <PageHeader kicker="Catalog discovery" title="Schema explorer" subtitle={<>database → schema → table → columns → policies, from real <span className="mono">pg_catalog</span> records. Schema hash <span className="mono">{data.schema_hash.slice(7, 19)}</span>.</>} />
      <div className="grid lg:grid-cols-[360px_1fr] gap-4 items-start">
        <Card title="Catalog tree" padded>
          <Input aria-label="Filter tree" placeholder="Filter tables or policies…" value={filter} onChange={(e) => setFilter(e.target.value)} className="mb-3" />
          <ul role="tree" aria-label="Catalog tree" className="grid gap-0.5 max-h-[64vh] overflow-auto scroll-thin text-[13px]">
            <li role="treeitem" aria-expanded="true" className="flex items-center gap-2 font-bold py-1"><Database size={14} aria-hidden /> {data.database}</li>
            {[...bySchema.entries()].map(([schema, ts]) => {
              const isOpen = open[schema] ?? true;
              return (
                <li key={schema} role="none">
                  <button type="button" role="treeitem" aria-expanded={isOpen} onClick={() => setOpen((o) => ({ ...o, [schema]: !isOpen }))} className="t-fast flex items-center gap-1.5 pl-3 py-1 w-full hover:bg-hover rounded">
                    {isOpen ? <ChevronDown size={14} aria-hidden /> : <ChevronRight size={14} aria-hidden />}<Layers size={14} aria-hidden /> <b>{schema}</b> <span className="text-muted">({ts.length})</span>
                  </button>
                  {isOpen && (
                    <ul role="group" className="ml-6 grid gap-0.5">
                      {ts.map((t) => {
                        const pols = data.policies.filter((p) => p.table === q(t));
                        return (
                          <li key={q(t)} role="none">
                            <button type="button" role="treeitem" aria-selected={sel === q(t)} data-testid={`tree-${q(t)}`} onClick={() => setSp({ table: q(t) })}
                              className={clsx("t-fast w-full text-left flex items-center gap-1.5 px-2 py-1 rounded hover:bg-hover", sel === q(t) && "bg-raised shadow-[inset_2px_0_0_var(--teal)]")}>
                              {t.kind === "view" || t.kind === "materialized_view" ? <Eye size={13} aria-hidden /> : <Table2 size={13} aria-hidden />}
                              <span className="mono truncate">{t.name}</span><span className="ml-auto flex gap-1 items-center"><Badges t={t} />{pols.length > 0 && <span className="text-[10px] text-muted mono">{pols.length}p</span>}</span>
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </li>
              );
            })}
          </ul>
          {data.functions.length > 0 && (
            <div className="mt-3">
              <div className="pl-3 text-xs uppercase tracking-wide text-muted">Functions</div>
              <ul className="ml-6 grid gap-0.5">{data.functions.map((f) => (
                <li key={`${f.schema}.${f.name}.${f.identity_args}`} className="flex items-center gap-1.5 px-2 py-1 text-[12px]"><FunctionSquare size={13} aria-hidden /><span className="mono truncate">{f.name}({f.identity_args})</span>
                  {f.security_definer && <Lozenge tone="amber">Definer</Lozenge>}</li>))}</ul>
            </div>
          )}
        </Card>
        <Card>{current ? <Detail snap={data} t={current} /> : <EmptyState title="Select a table or view">Markers show RLS, FORCE, view security context and policy counts. Everything here is a catalog fact; behaviour is proven in the matrix.</EmptyState>}</Card>
      </div>
    </div>
  );
}
