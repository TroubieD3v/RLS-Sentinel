import { ArrowRight, Database, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip as RTooltip, XAxis, YAxis } from "recharts";
import { PageHeader } from "@/components/Shell";
import { AsciiHero } from "@/design-system/AsciiHero";
import {
  Button, Card, CoverageBar, DemoTag, EmptyState, ErrorState, EvidenceLozenge, ModeBadge, SeverityLozenge, Skeleton, Stat, StatusLozenge,
} from "@/design-system/ui";
import { FixturePicker, LiveRun, RunButton } from "@/features/RunPanel";
import { useRunJob } from "@/features/useRunJob";
import { GraphCanvas, GraphLegend } from "@/graph/GraphCanvas";
import { fmtDate, shortHash, timeAgo } from "@/lib/format";
import { useActiveRun, useFindings, useHistory, useRunDetail, useRunGraph, useSnapshot } from "@/lib/queries";

function QuickStart() {
  const job = useRunJob();
  const [fx, setFx] = useState({ fixture: "", variant: "vulnerable" });
  const busy = job.state.phase === "starting" || job.state.phase === "running";
  return (
    <Card title="Quick start" subtitle="Pick a synthetic fixture, run the real verification harness, then review evidence." id="quickstart">
      <div className="grid gap-4">
        <FixturePicker fixture={fx.fixture} variant={fx.variant} onChange={(f, v) => setFx({ fixture: f, variant: v })} />
        <RunButton busy={busy} disabled={!fx.fixture} onClick={() => void job.start({ fixture: fx.fixture, variant: fx.variant })} />
        {job.state.phase !== "idle" && <LiveRun state={job.state} onCancel={() => void job.cancel()} />}
      </div>
    </Card>
  );
}

function Welcome() {
  return (
    <div className="grid gap-5 lg:grid-cols-[1.1fr_1fr] items-start">
      <div className="card p-5 grid gap-4" data-testid="welcome">
        <div>
          <div className="text-[11px] tracking-[0.2em] uppercase text-muted">Access intelligence</div>
          <h1 className="text-[28px] font-bold leading-tight mt-1">Database access. Verified.</h1>
          <p className="text-muted mt-2 max-w-prose">
            Permissions are not proof. RLS Sentinel reads the real PostgreSQL catalog, then executes reproducible allow/deny tests as genuinely different roles
            in a disposable database and tells you which grant or policy controlled each result.
          </p>
        </div>
        <AsciiHero />
        <ul className="text-[13px] text-muted grid gap-1.5">
          <li><ShieldCheck size={14} className="inline tone-teal mr-1.5" aria-hidden />Source databases: read-only catalog queries, no row data.</li>
          <li><Database size={14} className="inline tone-violet mr-1.5" aria-hidden />Mutating tests: only in disposable PostgreSQL, always rolled back.</li>
        </ul>
      </div>
      <QuickStart />
    </div>
  );
}

function CoveragePanel({ runId }: { runId: string }) {
  const d = useRunDetail(runId);
  const c = d.data?.summary?.coverage;
  if (d.isLoading) return <Skeleton className="h-40" />;
  if (!c) return <EmptyState title="No coverage yet">This run has no executed assertions (a catalog-only scan).</EmptyState>;
  return (
    <div className="grid gap-3">
      <CoverageBar passed={c.passed} failed={c.failed} inconclusive={c.inconclusive} notExecuted={c.not_executed} total={c.expected_assertions} />
      <pre className="mono card-flat p-3 m-0 overflow-auto scroll-thin" data-testid="coverage-panel">{d.data?.summary?.panel}</pre>
      <p className="text-xs text-muted">
        {c.rls_exercised} of {c.decided} decided assertions were resolved by the RLS layer itself; {c.grant_gate_only} were stopped at the SQL GRANT gate.
        Scanned tables are not assurance: only assertions that executed with a valid context count as verified.
      </p>
    </div>
  );
}

export default function Overview() {
  const { run, runs, isLoading, error, refetch } = useActiveRun();
  const detail = useRunDetail(run?.id);
  const snap = useSnapshot(run?.snapshot_id);
  const findings = useFindings({ run_id: run?.id, limit: 200 });
  const history = useHistory();
  const graph = useRunGraph(run?.id, { max_nodes: 60, depth: 2 });

  const counts = useMemo(() => {
    const items = findings.data?.items ?? [];
    return {
      confirmed: items.filter((f) => f.evidence_class === "CONFIRMED_VIOLATION").length,
      static: items.filter((f) => f.evidence_class === "CONFIGURATION_RISK").length,
      inconclusive: items.filter((f) => f.evidence_class === "INCONCLUSIVE").length,
      byClass: ["CONFIRMED_VIOLATION", "CONFIGURATION_RISK", "INCONCLUSIVE"].map((k) => ({ name: k.replace("_", " ").toLowerCase().replace("_", " "), count: items.filter((f) => f.evidence_class === k).length })),
    };
  }, [findings.data]);

  const policyByCmd = useMemo(() => {
    const m = new Map<string, { name: string; permissive: number; restrictive: number }>();
    for (const p of snap.data?.policies ?? []) {
      const r = m.get(p.command) ?? { name: p.command, permissive: 0, restrictive: 0 };
      if (p.permissive) r.permissive++; else r.restrictive++;
      m.set(p.command, r);
    }
    return ["SELECT", "INSERT", "UPDATE", "DELETE", "ALL"].map((k) => m.get(k) ?? { name: k, permissive: 0, restrictive: 0 });
  }, [snap.data]);

  if (isLoading) return <div className="grid gap-4"><Skeleton className="h-10 w-72" /><div className="grid grid-cols-2 lg:grid-cols-6 gap-3">{Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-24" />)}</div></div>;
  if (error) return <ErrorState error={error} onRetry={() => void refetch()} />;
  if (!run || runs.length === 0) return <Welcome />;

  const cov = detail.data?.summary?.coverage;
  const isFixture = !!run.fixture;
  const series = (history.data ?? []).filter((h) => h.kind === "lab" && h.status === "completed").slice(0, 30).reverse()
    .map((h, i) => ({ i: i + 1, coverage: h.verified_coverage_pct, failed: h.failed, label: `${h.fixture}:${h.variant}` }));

  return (
    <div className="grid gap-5">
      <PageHeader
        kicker="Access intelligence"
        title="Command center"
        subtitle={<>Database permissions are not assumptions. Verify them. Showing <b className="mono">{run.fixture ?? "scan"}{run.variant ? `:${run.variant}` : ""}</b> · {fmtDate(run.started_at)}.</>}
        actions={<>{isFixture && <DemoTag />}<ModeBadge mode={run.environment_mode} /><Link to="/studio"><Button variant="primary">New verification <ArrowRight size={14} aria-hidden /></Button></Link></>}
      />
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
        <Stat testId="stat-tables" label="Tables inspected" value={snap.data?.coverage.tables_seen ?? "…"} hint={`${snap.data?.coverage.schemas_seen ?? 0} schemas · PG ${snap.data?.postgres_version ?? ""}`} />
        <Stat testId="stat-policies" label="Policies" value={snap.data?.coverage.policies_seen ?? "…"} tone="violet" hint={`${snap.data?.coverage.roles_seen ?? 0} roles`} />
        <Stat testId="stat-tests" label="Actor/resource tests" value={cov?.expected_assertions ?? 0} hint={cov ? `${cov.decided} decided` : "catalog scan"} />
        <Stat testId="stat-confirmed" label="Confirmed violations" value={counts.confirmed} tone={counts.confirmed ? "coral" : "teal"} hint="runtime-proven" />
        <Stat testId="stat-static" label="Static risks" value={counts.static} tone={counts.static ? "amber" : undefined} hint="catalog inference" />
        <Stat testId="stat-inconclusive" label="Inconclusive" value={cov?.inconclusive ?? counts.inconclusive} tone="blue" hint="unknown ≠ safe" />
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <Card title="Security coverage" subtitle="Verified versus unverified boundaries" id="coverage" className="xl:col-span-2"><CoveragePanel runId={run.id} /></Card>
        <Card title="Findings by evidence class" subtitle="Counts for the active run" id="by-class">
          <div style={{ height: 210 }} role="img" aria-label={`Findings: ${counts.confirmed} confirmed, ${counts.static} configuration risks, ${counts.inconclusive} inconclusive`}>
            <ResponsiveContainer>
              <BarChart data={counts.byClass} layout="vertical" margin={{ left: 8, right: 16 }}>
                <CartesianGrid stroke="var(--border)" horizontal={false} />
                <XAxis type="number" allowDecimals={false} stroke="var(--muted)" fontSize={11} />
                <YAxis type="category" dataKey="name" width={118} stroke="var(--muted)" fontSize={11} />
                <RTooltip contentStyle={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12 }} cursor={{ fill: "var(--surface-hover)" }} />
                <Bar dataKey="count" fill="var(--violet)" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <Card title="Top authorization-risk findings" id="top-findings" className="xl:col-span-2" actions={<Link to="/findings" className="text-xs text-sky underline">All findings</Link>}>
          {findings.isLoading ? <Skeleton className="h-32" /> : (findings.data?.items.length ?? 0) === 0 ? (
            <EmptyState title="No findings in this run">Zero findings is not proof of safety: check the coverage card for what was actually verified.</EmptyState>
          ) : (
            <ul className="grid gap-2">
              {findings.data!.items.slice(0, 6).map((f) => (
                <li key={f.id}>
                  <Link to={`/findings?id=${f.id}`} className="t-fast card-flat flex items-start gap-3 p-2.5 hover:bg-hover">
                    <SeverityLozenge severity={f.severity} />
                    <div className="min-w-0 grow">
                      <div className="text-[13px] font-semibold truncate">{f.rule_id} · {f.title}</div>
                      <div className="text-xs text-muted truncate">{f.summary}</div>
                    </div>
                    <EvidenceLozenge cls={f.evidence_class} />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card title="Policies by operation" subtitle="Permissive vs restrictive" id="policies-by-cmd">
          <div style={{ height: 210 }} role="img" aria-label="Number of permissive and restrictive policies per SQL command">
            <ResponsiveContainer>
              <BarChart data={policyByCmd} margin={{ left: -18, right: 6 }}>
                <CartesianGrid stroke="var(--border)" vertical={false} />
                <XAxis dataKey="name" stroke="var(--muted)" fontSize={11} />
                <YAxis allowDecimals={false} stroke="var(--muted)" fontSize={11} />
                <RTooltip contentStyle={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12 }} cursor={{ fill: "var(--surface-hover)" }} />
                <Bar dataKey="permissive" stackId="a" fill="var(--violet)" name="permissive" />
                <Bar dataKey="restrictive" stackId="a" fill="var(--blue)" name="restrictive" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <Card title="Access graph preview" subtitle="Roles, grants, policies and tables (capped, deterministic layout)" id="graph-preview" className="xl:col-span-2" actions={<Link to="/graph" className="text-xs text-sky underline">Open graph</Link>}>
          {graph.data ? <><GraphCanvas data={graph.data} selectedId={null} compact height={300} /><div className="mt-2"><GraphLegend /></div></> : <Skeleton className="h-72" />}
        </Card>
        <div className="grid gap-5 content-start">
          <Card title="Coverage over time" subtitle="Real verified coverage of each past run" id="coverage-trend">
            {series.length < 2 ? <p className="text-[13px] text-muted">Run at least two verifications to see a trend.</p> : (
              <div style={{ height: 160 }} role="img" aria-label="Verified coverage percentage across runs">
                <ResponsiveContainer>
                  <LineChart data={series} margin={{ left: -18, right: 8 }}>
                    <CartesianGrid stroke="var(--border)" vertical={false} />
                    <XAxis dataKey="i" stroke="var(--muted)" fontSize={11} />
                    <YAxis domain={[0, 100]} stroke="var(--muted)" fontSize={11} />
                    <RTooltip contentStyle={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12 }} />
                    <Line type="monotone" dataKey="coverage" stroke="var(--teal)" strokeWidth={2} dot={{ r: 2 }} name="verified %" />
                    <Line type="monotone" dataKey="failed" stroke="var(--coral)" strokeWidth={2} dot={{ r: 2 }} name="failed cases" />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            )}
          </Card>
          <Card title="Recent runs" id="recent-runs">
            <ol className="grid gap-2" data-testid="recent-runs">
              {runs.slice(0, 6).map((r) => (
                <li key={r.id} className="flex items-center gap-2 text-[13px]">
                  <StatusLozenge status={r.status} />
                  <span className="truncate font-medium">{r.fixture ?? "scan"}{r.variant ? ` · ${r.variant}` : ""}</span>
                  <span className="ml-auto text-xs text-muted shrink-0" title={shortHash(String(r.version_info?.schema_hash ?? ""))}>{timeAgo(r.started_at)}</span>
                </li>
              ))}
            </ol>
          </Card>
        </div>
      </div>
      <QuickStart />
    </div>
  );
}
