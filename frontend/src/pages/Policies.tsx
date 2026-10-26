import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import type { Finding, PolicyRec } from "@/api/types";
import { PageHeader } from "@/components/Shell";
import { Card, EmptyState, ErrorState, Lozenge, ProvenanceLozenge, Select, SeverityLozenge, Skeleton } from "@/design-system/ui";
import { useActiveRun, useCases, useFindings, useSnapshot } from "@/lib/queries";
import { Sql } from "@/lib/sql";

const CMDS = ["SELECT", "INSERT", "UPDATE", "DELETE", "ALL"] as const;

function PolicyCard({ p, warnings, tests }: { p: PolicyRec; warnings: Finding[]; tests: { id: string; status: string }[] }) {
  return (
    <li className="card p-4 grid gap-2.5" data-testid={`policy-${p.name}`}>
      <div className="flex gap-2 items-center flex-wrap">
        <h3 className="mono font-bold">{p.name}</h3>
        <Lozenge tone={p.permissive ? "violet" : "blue"}>{p.permissive ? "Permissive · OR" : "Restrictive · AND"}</Lozenge>
        <Lozenge tone="muted">{p.command}</Lozenge>
        <ProvenanceLozenge kind="catalog" />
      </div>
      <div className="flex gap-1.5 flex-wrap items-center text-xs"><span className="text-muted">Applies to roles:</span>
        {p.roles.map((r) => <span key={r} className={`mono border rounded-full px-2 py-0.5 ${r === "PUBLIC" ? "tone-amber" : ""}`} style={{ borderColor: r === "PUBLIC" ? "currentColor" : "var(--border)" }}>{r}</span>)}</div>
      <div className="grid md:grid-cols-2 gap-3">
        <div className="card-flat p-3"><div className="text-[10px] font-bold uppercase tracking-widest text-muted mb-1">USING (filters existing rows)</div><Sql text={p.using_expr} /></div>
        <div className="card-flat p-3"><div className="text-[10px] font-bold uppercase tracking-widest text-muted mb-1">WITH CHECK (validates new rows)</div><Sql text={p.check_expr} />
          {p.check_expr == null && (p.command === "UPDATE" || p.command === "ALL") && p.using_expr && <p className="text-[11px] text-muted mt-1">Omitted: UPDATE falls back to USING for the new row.</p>}</div>
      </div>
      {(p.deps.columns.length > 0 || p.deps.relations.length > 0) && (
        <p className="text-xs text-muted">Depends on (pg_depend): <span className="mono">{[...p.deps.columns.slice(0, 6), ...p.deps.relations.slice(0, 3)].join(", ")}</span></p>)}
      {p.provenance.path && <p className="text-xs text-muted mono">{p.provenance.path}:{p.provenance.line}</p>}
      {warnings.length > 0 && (
        <ul className="grid gap-1" aria-label="Warnings">{warnings.map((f) => (
          <li key={f.id}><Link to={`/findings?id=${f.id}`} className="flex gap-2 items-start text-[12px] hover:underline"><SeverityLozenge severity={f.severity} /><span><b>{f.rule_id}</b> {f.summary}</span></Link></li>))}</ul>)}
      {tests.length > 0 && <p className="text-xs"><span className="text-muted">Linked runtime tests: </span>{tests.slice(0, 8).map((t) => <span key={t.id} className="mono mr-2">{t.status === "FAIL" ? "✕" : t.status === "PASS" ? "✓" : "?"} {t.id}</span>)}{tests.length > 8 && `+${tests.length - 8}`}</p>}
    </li>
  );
}

export default function PolicyExplorer() {
  const { run, isLoading, error } = useActiveRun();
  const snap = useSnapshot(run?.snapshot_id);
  const findings = useFindings({ run_id: run?.id, limit: 500 });
  const cases = useCases(run?.id);
  const [sp, setSp] = useSearchParams();
  const [cmd, setCmd] = useState("");
  const table = sp.get("table") ?? "";
  const data = snap.data;
  const tables = useMemo(() => Array.from(new Set((data?.policies ?? []).map((p) => p.table))).sort(), [data]);
  const shown = useMemo(() => (data?.policies ?? []).filter((p) => (!table || p.table === table) && (!cmd || p.command === cmd)), [data, table, cmd]);
  const grouped = useMemo(() => {
    const m = new Map<string, PolicyRec[]>();
    for (const p of shown) m.set(p.table, [...(m.get(p.table) ?? []), p]);
    return m;
  }, [shown]);
  if (isLoading || snap.isLoading) return <Skeleton className="h-96" />;
  if (error || snap.error) return <ErrorState error={error ?? snap.error} />;
  if (!run || !data) return <EmptyState title="No policies loaded">Run a scan or verification first.</EmptyState>;
  const warnFor = (p: PolicyRec) => (findings.data?.items ?? []).filter((f) => f.objects.policy === p.name && f.objects.table === p.table);
  const testsFor = (p: PolicyRec) => (cases.data ?? []).filter((c) => c.table === p.table && c.evidence.raw.applicable_policies.some((x) => x.name === p.name))
    .map((c) => ({ id: c.case_id, status: c.status }));
  return (
    <div className="grid gap-4">
      <PageHeader kicker="Policy inspection" title="Policy explorer" subtitle="Per-command cards from pg_policy. Permissive policies combine with OR; restrictive with AND; a restrictive policy alone never grants access." />
      <Card>
        <div className="flex flex-wrap gap-3 items-end">
          <label className="grid gap-1 text-xs text-muted">Table<Select aria-label="Table" value={table} onChange={(e) => setSp(e.target.value ? { table: e.target.value } : {})} className="w-64"><option value="">All tables with policies</option>{tables.map((t) => <option key={t}>{t}</option>)}</Select></label>
          <label className="grid gap-1 text-xs text-muted">Command<Select aria-label="Command" value={cmd} onChange={(e) => setCmd(e.target.value)} className="w-40"><option value="">All</option>{CMDS.map((c) => <option key={c}>{c}</option>)}</Select></label>
          <span className="ml-auto text-xs text-muted mono">{shown.length} policies</span>
        </div>
      </Card>
      {shown.length === 0 && <EmptyState title="No policies match">RLS-enabled tables without policies deny by default; tables with RLS disabled ignore policies.</EmptyState>}
      {[...grouped.entries()].map(([t, ps]) => {
        const rec = data.tables.find((x) => `${x.schema}.${x.name}` === t);
        return (
          <section key={t} aria-label={`Policies on ${t}`} className="grid gap-3">
            <h2 className="mono font-bold flex gap-2 items-center flex-wrap">{t}{rec && (rec.rls_enabled ? <Lozenge tone="teal">RLS on</Lozenge> : <Lozenge tone="amber">RLS off — policies inactive</Lozenge>)}{rec?.rls_forced && <Lozenge tone="violet">Force</Lozenge>}</h2>
            <ul className="grid gap-3 xl:grid-cols-2 list-none p-0 m-0">{ps.map((p) => <PolicyCard key={p.name} p={p} warnings={warnFor(p)} tests={testsFor(p)} />)}</ul>
          </section>
        );
      })}
    </div>
  );
}
