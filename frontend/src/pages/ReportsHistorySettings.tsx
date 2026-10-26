import { useQueryClient } from "@tanstack/react-query";
import { Download, GitCompare, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip as RTooltip, XAxis, YAxis } from "recharts";
import { api, download, getToken, setToken } from "@/api/client";
import type { Finding } from "@/api/types";
import { describeError, PageHeader } from "@/components/Shell";
import { Button, Card, DemoTag, EmptyState, ErrorState, Field, Input, Lozenge, Select, Skeleton, StatusLozenge } from "@/design-system/ui";
import { fmtDate, shortHash } from "@/lib/format";
import { qk, useAudit, useHealth, useHistory, useRules, useRuns, useSuppressions } from "@/lib/queries";
import { useApp } from "@/state/app";

const FORMATS = [["html", "HTML"], ["md", "Markdown"], ["json", "JSON"], ["sarif", "SARIF 2.1.0"], ["csv", "CSV"]] as const;

export function ReportsPage() {
  const runs = useRuns();
  const { toast } = useApp();
  const qc = useQueryClient();
  if (runs.isLoading) return <Skeleton className="h-64" />;
  if (runs.error) return <ErrorState error={runs.error} />;
  const list = (runs.data ?? []).filter((r) => r.status === "completed");
  return (
    <div className="grid gap-4">
      <PageHeader kicker="Evidence-centered reports" title="Reports" subtitle="Every export states scope, the independent expectation, observed result, provenance, reproducibility data, remediation caveats and limitations. No row contents, credentials or tokens are included." />
      {list.length === 0 ? <EmptyState title="No completed runs">Run a verification to generate a report archive.</EmptyState> : (
        <Card padded={false}>
          <div className="overflow-auto scroll-thin"><table className="w-full text-[13px]" data-testid="reports-table">
            <caption className="sr-only">Run archive</caption>
            <thead><tr className="text-left text-muted text-xs uppercase tracking-wide"><th className="p-3">Run</th><th className="p-3">Started</th><th className="p-3">Result</th><th className="p-3">Export</th><th className="p-3" /></tr></thead>
            <tbody>{list.map((r) => (
              <tr key={r.id} className="border-t border-line">
                <td className="p-3"><div className="font-semibold flex items-center gap-2">{r.fixture ?? "catalog scan"}{r.variant ? ` · ${r.variant}` : ""}{r.fixture && <DemoTag />}</div><div className="mono text-xs text-muted">{r.id.slice(0, 12)} · {r.environment_mode} · schema {shortHash(String(r.version_info?.schema_hash ?? ""))}</div></td>
                <td className="p-3 text-muted">{fmtDate(r.started_at)}</td>
                <td className="p-3 mono text-xs">{r.coverage.expected_assertions ? <>pass {r.coverage.passed} · <b className={r.coverage.failed ? "tone-coral" : ""}>fail {r.coverage.failed}</b> · inc {r.coverage.inconclusive}<br /><span className="text-muted">{r.coverage.verified_coverage_pct}% of {r.coverage.expected_assertions} verified</span></> : <span className="text-muted">catalog only</span>}</td>
                <td className="p-3"><div className="flex gap-1.5 flex-wrap">{FORMATS.map(([f, label]) => (
                  <Button key={f} size="sm" data-testid={`dl-${f}`} onClick={() => void download(`/reports/${r.id}?format=${f}`, `rls-sentinel-${r.id.slice(0, 8)}.${f}`).then(() => toast("teal", `${label} report downloaded.`)).catch((e) => toast("coral", describeError(e)))}><Download size={12} aria-hidden /> {label}</Button>))}</div></td>
                <td className="p-3 text-right"><Button size="sm" variant="ghost" aria-label="Delete run" onClick={() => { if (confirm("Delete this run, its findings and evidence?")) void api(`/test-runs/${r.id}`, { method: "DELETE" }).then(() => { void qc.invalidateQueries(); toast("blue", "Run deleted (audited)."); }); }}><Trash2 size={14} aria-hidden /></Button></td>
              </tr>))}</tbody></table></div>
        </Card>
      )}
    </div>
  );
}

interface DiffResp { diff: { changes: { category: string; summary: string; risk: string; textual_only: boolean }[]; behavioral: { case_id: string; before: string; after: string; transition: string; summary: string }[]; summary: Record<string, number>; caveats: string[] };
  finding_labels: Record<"new" | "resolved" | "persisting" | "unverified", { rule_id: string; subject: string; severity: string }[]> ; drift_findings: Finding[] }

export function HistoryPage() {
  const hist = useHistory();
  const runs = useRuns();
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [res, setRes] = useState<DiffResp | null>(null);
  const [busy, setBusy] = useState(false);
  const { toast } = useApp();
  const done = (runs.data ?? []).filter((r) => r.status === "completed" && r.kind !== "whatif_sandbox");
  const series = useMemo(() => [...(hist.data ?? [])].filter((h) => h.status === "completed" && h.kind === "lab").reverse().map((h, i) => ({ n: i + 1, coverage: h.verified_coverage_pct, failed: h.failed, inconclusive: h.inconclusive, name: `${h.fixture}:${h.variant}` })), [hist.data]);
  if (hist.isLoading) return <Skeleton className="h-64" />;
  if (hist.error) return <ErrorState error={hist.error} />;
  return (
    <div className="grid gap-4">
      <PageHeader kicker="Regressions & drift" title="History" subtitle="Real runs only. Compare two runs to see policy drift, new / resolved / persisting / unverified findings and test-outcome changes." />
      <Card title="Verified coverage and failures per run" id="trend">
        {series.length < 2 ? <p className="text-[13px] text-muted">Two or more completed lab runs are needed for a trend.</p> : (
          <div style={{ height: 240 }} role="img" aria-label="Line chart of verified coverage, failed and inconclusive cases per run">
            <ResponsiveContainer><LineChart data={series} margin={{ left: -10, right: 12 }}>
              <CartesianGrid stroke="var(--border)" vertical={false} /><XAxis dataKey="n" stroke="var(--muted)" fontSize={11} /><YAxis stroke="var(--muted)" fontSize={11} />
              <RTooltip contentStyle={{ background: "var(--surface)", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12 }} labelFormatter={(n) => series[Number(n) - 1]?.name ?? ""} /><Legend />
              <Line dataKey="coverage" name="verified %" stroke="var(--teal)" strokeWidth={2} dot={{ r: 2 }} /><Line dataKey="failed" name="failed" stroke="var(--coral)" strokeWidth={2} dot={{ r: 2 }} />
              <Line dataKey="inconclusive" name="inconclusive" stroke="var(--amber)" strokeWidth={2} strokeDasharray="5 4" dot={{ r: 2 }} /></LineChart></ResponsiveContainer>
          </div>)}
      </Card>
      <Card title="Compare two runs" id="compare">
        <div className="flex gap-3 flex-wrap items-end">
          {([["From (older)", a, setA], ["To (newer)", b, setB]] as const).map(([label, v, set]) => (
            <Field key={label} label={label} htmlFor={`cmp-${label}`}><Select id={`cmp-${label}`} aria-label={label} value={v} onChange={(e) => set(e.target.value)} className="w-72"><option value="" />{done.map((r) => <option key={r.id} value={r.id}>{r.fixture ?? "scan"}:{r.variant ?? ""} · {fmtDate(r.started_at)}</option>)}</Select></Field>))}
          <Button variant="primary" disabled={!a || !b || a === b} loading={busy} data-testid="compare-btn" onClick={() => { setBusy(true); api<DiffResp>("/diff", { method: "POST", body: { from_run_id: a, to_run_id: b } }).then((r) => setRes(r.data)).catch((e) => toast("coral", describeError(e))).finally(() => setBusy(false)); }}>
            <GitCompare size={14} aria-hidden /> Compare</Button>
        </div>
        {res && (
          <div className="mt-4 grid gap-4" data-testid="diff-result">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
              {(["new", "resolved", "persisting", "unverified"] as const).map((k) => <div key={k} className="card-flat p-3"><div className="text-[11px] uppercase tracking-widest text-muted">{k}</div><div className="mono text-2xl font-bold">{res.finding_labels[k].length}</div></div>)}
            </div>
            <div className="text-xs text-muted">{res.diff.summary.changes} structural changes · {res.diff.summary.risk_higher} higher-risk · {res.diff.summary.risk_lower} lower-risk · {res.diff.summary.textual_only} text-only · {res.diff.summary.regressions} regressions · {res.diff.summary.resolved} resolved cases</div>
            <ul tabIndex={0} aria-label="Catalog changes" className="grid gap-1 text-[12px] max-h-72 overflow-auto scroll-thin">{res.diff.changes.map((c, i) => <li key={i} className="flex gap-2"><Lozenge tone={c.risk === "higher" ? "coral" : c.risk === "lower" ? "teal" : "muted"}>{c.risk}</Lozenge><span className="mono text-muted">{c.category}</span><span>{c.summary}{c.textual_only ? " (text only)" : ""}</span></li>)}</ul>
            {res.diff.behavioral.filter((x) => x.transition !== "unchanged").length > 0 && <ul className="grid gap-1 text-[12px]">{res.diff.behavioral.filter((x) => x.transition !== "unchanged").map((x) => <li key={x.case_id} className="mono">{x.transition === "regression" ? "✕" : x.transition === "resolved" ? "✓" : "·"} {x.case_id}: {x.before} → {x.after}</li>)}</ul>}
            <p className="text-xs text-muted">{res.diff.caveats.join(" ")}</p>
          </div>)}
      </Card>
      <Card title="Run archive" padded={false} id="archive">
        <div className="overflow-auto scroll-thin"><table className="w-full text-[12px]"><caption className="sr-only">Run history</caption>
          <thead><tr className="text-left text-muted uppercase tracking-wide"><th className="p-2.5">When</th><th className="p-2.5">Run</th><th className="p-2.5">Status</th><th className="p-2.5">Pass</th><th className="p-2.5">Fail</th><th className="p-2.5">Inconcl.</th><th className="p-2.5">Verified</th><th className="p-2.5">Findings</th></tr></thead>
          <tbody>{(hist.data ?? []).map((h) => <tr key={h.run_id} className="border-t border-line"><td className="p-2.5 text-muted">{fmtDate(h.started_at)}</td><td className="p-2.5 mono">{h.fixture ?? "scan"}{h.variant ? `:${h.variant}` : ""}</td><td className="p-2.5"><StatusLozenge status={h.status} /></td>
            <td className="p-2.5 mono">{h.passed}</td><td className={`p-2.5 mono ${h.failed ? "tone-coral font-bold" : ""}`}>{h.failed}</td><td className="p-2.5 mono">{h.inconclusive}</td><td className="p-2.5 mono">{h.verified_coverage_pct}% / {h.expected}</td><td className="p-2.5 mono">{h.findings}</td></tr>)}</tbody></table></div>
      </Card>
    </div>
  );
}

export function SettingsPage() {
  const { theme, setTheme, reducedMotion, setReducedMotion, toast } = useApp();
  const health = useHealth();
  const rules = useRules();
  const audit = useAudit();
  const sups = useSuppressions();
  const qc = useQueryClient();
  const [tok, setTok] = useState("");
  const [days, setDays] = useState(90);
  return (
    <div className="grid gap-4">
      <PageHeader kicker="Preferences & diagnostics" title="Settings" />
      <div className="grid lg:grid-cols-2 gap-4 items-start">
        <Card title="Appearance" id="appearance">
          <div className="grid gap-3 max-w-md">
            <Field label="Theme" htmlFor="theme"><Select id="theme" value={theme} onChange={(e) => setTheme(e.target.value as "system" | "dark" | "light")}><option value="system">Follow operating system</option><option value="dark">Dark — Midnight Observatory</option><option value="light">Light</option></Select></Field>
            <label className="flex items-center gap-2 text-[13px]"><input type="checkbox" checked={reducedMotion} onChange={(e) => setReducedMotion(e.target.checked)} data-testid="reduced-motion" />Reduce motion (disables transitions and the blinking cursor)</label>
          </div>
        </Card>
        <Card title="API access" subtitle={`Server auth mode: ${health.data?.auth ?? "…"}`} id="api-access">
          <form className="grid gap-3 max-w-md" onSubmit={(e) => { e.preventDefault(); setToken(tok.trim()); setTok(""); void qc.invalidateQueries(); toast("teal", "Token stored for this tab only."); }}>
            <Field label="Bearer token (tab-scoped sessionStorage)" htmlFor="tok2"><Input id="tok2" type="password" autoComplete="off" value={tok} onChange={(e) => setTok(e.target.value)} placeholder={getToken() ? "••••••••" : "not set"} /></Field>
            <div className="flex gap-2"><Button type="submit" disabled={!tok.trim()}>Save token</Button><Button type="button" variant="ghost" onClick={() => { setToken(""); toast("blue", "Token cleared."); }}>Clear</Button></div>
          </form>
        </Card>
        <Card title="Diagnostics" id="diag">
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[13px]" data-testid="diagnostics-list">
            <dt className="text-muted">Version</dt><dd className="mono">{health.data?.version} · ruleset {health.data?.ruleset}</dd>
            <dt className="text-muted">Lab backend</dt><dd className="mono">{health.data?.lab.backend} — {health.data?.lab.detail}</dd>
            <dt className="text-muted">Metadata store</dt><dd className="mono">{health.data?.metadata_store}</dd>
            <dt className="text-muted">Source DB mutation</dt><dd className="mono">{health.data?.source_database_mutation}</dd>
            <dt className="text-muted">Rules</dt><dd>{rules.data?.length ?? "…"} versioned rules</dd>
          </dl>
        </Card>
        <Card title="Retention & deletion" subtitle="Delete stored runs, snapshots and aged audit data" id="retention">
          <div className="flex items-end gap-3"><Field label="Older than (days)" htmlFor="ret"><Input id="ret" type="number" min={1} value={days} onChange={(e) => setDays(Number(e.target.value))} className="w-28" /></Field>
            <Button variant="danger" onClick={() => { if (confirm(`Permanently delete runs and snapshots older than ${days} days?`)) void api<Record<string, number>>("/retention/purge", { method: "POST", body: { days } }).then((r) => { toast("blue", `Purged ${JSON.stringify(r.data)}`); void qc.invalidateQueries(); }).catch((e) => toast("coral", describeError(e))); }}>Purge…</Button></div>
        </Card>
      </div>
      <Card title="Suppressions" subtitle="Hide alerts without modifying results; each has an owner, reviewer and expiry" id="suppressions">
        {(sups.data?.length ?? 0) === 0 ? <p className="text-[13px] text-muted">None.</p> : (
          <ul className="grid gap-1.5 text-[12px]">{sups.data!.map((s) => <li key={s.id} className="card-flat px-3 py-2 flex gap-3 flex-wrap items-center"><Lozenge tone={s.active ? "amber" : "muted"}>{s.active ? "active" : "inactive"}</Lozenge><span className="mono font-bold">{s.rule_id}</span><span className="mono">{s.scope}</span><span className="text-muted">{s.reason}</span>
            <span className="text-muted ml-auto">owner {s.owner} · reviewer {s.reviewer} · expires {fmtDate(s.expires_at)}</span>{s.active && <Button size="sm" variant="ghost" onClick={() => void api(`/suppressions/${s.id}`, { method: "DELETE" }).then(() => qc.invalidateQueries({ queryKey: qk.suppressions }))}>Revoke</Button>}</li>)}</ul>)}
      </Card>
      <Card title="Audit log" subtitle="Append-only record of state-changing actions" id="audit" padded={false}>
        <div tabIndex={0} role="region" aria-label="Audit events" className="max-h-72 overflow-auto scroll-thin"><table className="w-full text-[12px]"><caption className="sr-only">Audit events</caption><tbody>{(audit.data ?? []).map((e) => <tr key={e.id} className="border-t border-line"><td className="p-2 text-muted whitespace-nowrap">{fmtDate(e.timestamp)}</td><td className="p-2 mono">{e.event_type}</td><td className="p-2 mono truncate max-w-xs">{e.target}</td><td className="p-2 text-muted">{e.actor}</td></tr>)}</tbody></table></div>
      </Card>
      <Card title="About" id="about">
        <p className="text-[13px]">RLS Sentinel {health.data?.version} · MIT license · see SECURITY.md for responsible disclosure and docs/limitations.md for what this tool cannot tell you.</p>
      </Card>
    </div>
  );
}
