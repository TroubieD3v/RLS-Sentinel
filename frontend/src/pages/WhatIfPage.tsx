import { useQueryClient } from "@tanstack/react-query";
import { FlaskConical, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, download, saveTextFile } from "@/api/client";
import type { CaseDelta, PolicyRec, WhatIf } from "@/api/types";
import { describeError, PageHeader } from "@/components/Shell";
import { Button, Card, CoverageBar, EmptyState, ErrorState, Lozenge, Select, Skeleton, Stat } from "@/design-system/ui";
import { qk, useActiveRun, useSnapshot, useSuggestions, useWhatIf, useWhatIfs } from "@/lib/queries";
import { SqlBlock } from "@/lib/sql";
import { useApp } from "@/state/app";

const BANNER = "SIMULATED IN DISPOSABLE DATABASE — NO LIVE CHANGES";

const qi = (n: string) => (/^[a-z_][a-z0-9_$]*$/.test(n) ? n : `"${n.replaceAll('"', '""')}"`);
function policyDdl(p: PolicyRec): string {
  const [s, t] = p.table.split(".");
  return `CREATE POLICY ${qi(p.name)} ON ${qi(s)}.${qi(t)}\n    AS ${p.permissive ? "PERMISSIVE" : "RESTRICTIVE"} FOR ${p.command} TO ${p.roles.join(", ")}` +
    (p.using_expr ? `\n    USING (${p.using_expr})` : "") + (p.check_expr ? `\n    WITH CHECK (${p.check_expr})` : "") + ";";
}

const KIND_LABEL: Record<string, { text: string; tone: string }> = {
  resolved: { text: "Resolved", tone: "tone-teal" }, regression: { text: "Regression: authorized access blocked", tone: "tone-coral" },
  broader_access: { text: "Broader access introduced", tone: "tone-coral" }, unchanged_failing: { text: "Still failing", tone: "tone-amber" },
  unknown_changed: { text: "Unknown", tone: "tone-blue" }, unchanged_passing: { text: "Unchanged (pass)", tone: "tone-muted" },
};

function Results({ w, baselineRunId }: { w: WhatIf; baselineRunId: string }) {
  const r = w.result;
  const { toast } = useApp();
  if (w.status === "queued" || w.status === "running") return <div role="status" className="card-flat p-4" data-testid="whatif-running">Replaying the full matrix in a disposable clone…</div>;
  if (w.status === "failed" || !r) return <ErrorState error={new Error(w.error ?? r?.apply_error ?? "The experiment failed.")} />;
  const bad = (r.summary.regression ?? 0) + (r.summary.broader_access ?? 0);
  const groups = Object.keys(KIND_LABEL).filter((k) => k !== "unchanged_passing");
  return (
    <div className="grid gap-4" data-testid="whatif-results">
      <div className="card p-4 grid gap-1" style={{ borderColor: r.verdict === "improves" ? "var(--teal)" : "var(--coral)" }} role="status">
        <div className="flex gap-2 items-center flex-wrap"><Lozenge tone={r.verdict === "improves" ? "teal" : r.verdict === "no_change" ? "muted" : "coral"}>{r.verdict.replace("_", " ")}</Lozenge>
          <b data-testid="whatif-verdict-text">{r.verdict_text}</b></div>
        <p className="text-xs text-muted">Re-verified by executing every test against the modified clone (PostgreSQL {r.postgres_version}, {r.duration_s}s). The text of the patch was never trusted.</p>
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Stat label="Resolved" value={r.summary.resolved ?? 0} tone="teal" testId="wi-resolved" />
        <Stat label="Regressions" value={r.summary.regression ?? 0} tone={r.summary.regression ? "coral" : undefined} testId="wi-regressions" />
        <Stat label="Broader access" value={r.summary.broader_access ?? 0} tone={r.summary.broader_access ? "coral" : undefined} />
        <Stat label="Still failing" value={r.summary.unchanged_failing ?? 0} tone="amber" />
      </div>
      <div className="grid md:grid-cols-2 gap-4">
        {([["Baseline", r.baseline_coverage], ["After draft (sandbox)", r.sandbox_coverage]] as const).map(([t, c]) => (
          <Card key={t} title={t} subtitle={`${c.verified_coverage_pct}% verified of ${c.expected_assertions}`}>
            <CoverageBar passed={c.passed} failed={c.failed} inconclusive={c.inconclusive} notExecuted={c.not_executed} total={c.expected_assertions} /></Card>))}
      </div>
      <Card title="Matrix diff" subtitle="Per expectation: before → after" id="matrix-diff">
        {groups.map((k) => {
          const rows = r.deltas.filter((d: CaseDelta) => d.kind === k);
          if (!rows.length) return null;
          return (
            <section key={k} className="mb-3" aria-label={KIND_LABEL[k].text}>
              <h4 className={`text-xs font-bold uppercase tracking-wide ${KIND_LABEL[k].tone}`}>{KIND_LABEL[k].text} · {rows.length}</h4>
              <ul className="grid gap-1 mt-1">{rows.map((d) => (
                <li key={d.case_id} className="text-[12px] flex gap-2 flex-wrap card-flat px-2 py-1"><span className="mono font-semibold">{d.case_id}</span><span className="text-muted">{d.actor} {d.operation} expected {d.expected}</span>
                  <span className="mono ml-auto">{d.before} → {d.after}</span>{d.detail && <span className="basis-full text-muted">{d.detail}</span>}</li>))}</ul>
            </section>
          );
        })}
        <p className="text-xs text-muted">{r.summary.unchanged_passing ?? 0} expectations passed before and after (not listed).</p>
      </Card>
      {r.snapshot_diff && r.snapshot_diff.changes.length > 0 && (
        <Card title="Catalog drift in the sandbox" subtitle="Structural signals only; behaviour is established by the tests above" id="snap-diff">
          <ul className="grid gap-1 text-[12px]">{r.snapshot_diff.changes.map((c, i) => (
            <li key={i} className="flex gap-2"><Lozenge tone={c.risk === "higher" ? "coral" : c.risk === "lower" ? "teal" : "muted"}>{c.risk}</Lozenge><span>{c.summary}{c.textual_only ? " (text only)" : ""}</span></li>))}</ul>
        </Card>
      )}
      <div className="flex gap-2 flex-wrap">
        <Button variant="primary" disabled={bad > 0} title={bad > 0 ? "Fix regressions before exporting a patch" : undefined} data-testid="export-patch"
          onClick={() => saveTextFile("rls-sentinel-patch.sql", `-- RLS Sentinel: vetted in a disposable clone (${r.postgres_version}); baseline schema ${r.baseline_schema_hash}\n-- ${r.verdict_text}\n-- FOR HUMAN REVIEW. Never applied automatically.\nBEGIN;\n${w.draft_sql.trim()}\nCOMMIT;\n`, "application/sql")}>
          Export SQL patch for review
        </Button>
        <Button onClick={() => void download(`/test-runs/${baselineRunId}/pytest?mode=spec`, "test_rls_authorization.py").catch((e: Error) => toast("coral", e.message))}>Export regression tests</Button>
      </div>
    </div>
  );
}

export default function WhatIfPage() {
  const { run, runs, isLoading, error } = useActiveRun();
  const labRuns = runs.filter((r) => r.kind === "lab" && r.status === "completed");
  const [sp] = useSearchParams();
  const [baseId, setBaseId] = useState("");
  const base = labRuns.find((r) => r.id === baseId) ?? (run?.kind === "lab" ? run : labRuns[0]);
  const snap = useSnapshot(base?.snapshot_id);
  const sugg = useSuggestions(base?.id);
  const [draft, setDraft] = useState(sp.get("draft") ?? "");
  const [lint, setLint] = useState<{ accepted: boolean; problems: string[] } | null>(null);
  const [wid, setWid] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const w = useWhatIf(wid);
  const hist = useWhatIfs();
  const qc = useQueryClient();
  const { toast } = useApp();
  useEffect(() => { if (w.data?.status === "completed" || w.data?.status === "failed") void qc.invalidateQueries({ queryKey: qk.whatifs }); }, [w.data?.status, qc]);

  const marks = useMemo(() => {
    const m: Record<number, "add" | "del"> = {};
    const lines = draft.split("\n");
    const out: string[] = [];
    lines.forEach((ln) => {
      const drop = /^\s*DROP\s+POLICY\s+(?:IF\s+EXISTS\s+)?("?[\w$]+"?)\s+ON\s+([\w."]+)/i.exec(ln);
      if (drop) {
        const pol = snap.data?.policies.find((p) => p.name === drop[1].replaceAll('"', '') && (p.table.endsWith(drop[2].replaceAll('"', '').split(".").pop()!)));
        if (pol) for (const l of policyDdl(pol).split("\n")) { out.push(l); m[out.length] = "del"; }
      }
      out.push(ln);
      if (ln.trim() && !ln.trim().startsWith("--")) m[out.length] = "add";
    });
    return { text: out.join("\n"), marks: m };
  }, [draft, snap.data]);

  if (isLoading) return <Skeleton className="h-96" />;
  if (error) return <ErrorState error={error} />;
  if (labRuns.length === 0) return <EmptyState title="Baseline needed" icon={<FlaskConical />}>The What-if Lab replays a fix against a baseline lab run. Run a verification on a fixture first.</EmptyState>;

  const submit = async () => {
    if (!base) return;
    setBusy(true); setWid(null);
    try {
      const r = await api<{ id: string }>("/what-if", { method: "POST", body: { run_id: base.id, draft_sql: draft } });
      setWid(r.data.id);
    } catch (e) { toast("coral", describeError(e)); } finally { setBusy(false); }
  };
  return (
    <div className="grid gap-4">
      <div className="sticky top-0 z-10 -mt-2 card px-4 py-2.5 flex items-center gap-2 font-bold tracking-wide text-[13px]" style={{ borderColor: "var(--amber)", color: "var(--amber)" }} role="note" data-testid="sandbox-banner">
        <ShieldAlert size={16} aria-hidden /> {BANNER}
      </div>
      <PageHeader kicker="Remediation simulation" title="What-if Policy Lab"
        subtitle="Edit a draft, replay the entire matrix in a disposable clone and see what improves, what breaks and what becomes broader. Nothing is ever sent to a source database." />
      <div className="grid xl:grid-cols-2 gap-4 items-start">
        <Card title="Original policies" subtitle={`Baseline run ${base?.fixture}:${base?.variant}`} id="orig"
          actions={<Select aria-label="Baseline run" value={base?.id ?? ""} onChange={(e) => { setBaseId(e.target.value); setWid(null); }} className="w-56 !h-8 text-xs">{labRuns.map((r) => <option key={r.id} value={r.id}>{r.fixture}:{r.variant} · {r.id.slice(0, 6)}</option>)}</Select>}>
          <div tabIndex={0} role="region" aria-label="Original policies list" className="max-h-[420px] overflow-auto scroll-thin grid gap-2">
            {(snap.data?.policies ?? []).map((p) => <SqlBlock key={`${p.table}.${p.name}`} text={`-- ${p.table}\n${policyDdl(p)}`} label={`Policy ${p.name}`} />)}
            {snap.isLoading && <Skeleton className="h-24" />}
          </div>
        </Card>
        <Card title="Proposed change (draft)" subtitle="Policy / RLS / grant / view / function DDL only — enforced by an AST allow-list" id="draft">
          <div className="grid gap-3">
            <textarea aria-label="Draft SQL" data-testid="draft-sql" spellCheck={false} value={draft} onChange={(e) => { setDraft(e.target.value); setLint(null); }}
              placeholder={"DROP POLICY art_hold_update ON articles;\nCREATE POLICY art_hold_update ON articles AS RESTRICTIVE FOR UPDATE TO PUBLIC USING (NOT legal_hold);"}
              className="mono w-full h-52 card-flat p-3 outline-none scroll-thin resize-y" />
            <div className="flex gap-2 flex-wrap">
              <Button onClick={() => void api<{ accepted: boolean; problems: string[] }>("/what-if/lint", { method: "POST", body: { draft_sql: draft } }).then((r) => setLint(r.data)).catch((e) => toast("coral", describeError(e)))} disabled={!draft.trim()}>Check allow-list</Button>
              <Button variant="primary" onClick={() => void submit()} loading={busy || w.data?.status === "running" || w.data?.status === "queued"} disabled={!draft.trim()} data-testid="run-whatif">
                <FlaskConical size={14} aria-hidden /> Replay in sandbox</Button>
            </div>
            {lint && (lint.accepted ? <Lozenge tone="teal">Accepted by the sandbox allow-list</Lozenge> : <ul role="alert" className="text-[12px] tone-coral list-disc pl-4">{lint.problems.map((p) => <li key={p}>{p}</li>)}</ul>)}
            {draft.trim() && <div><div className="text-xs font-bold uppercase tracking-wide text-muted mb-1">Change rail</div><SqlBlock text={marks.text} marks={marks.marks} label="Draft with change markers" /></div>}
          </div>
        </Card>
      </div>
      {sugg.data && sugg.data.suggestions.length > 0 && (
        <Card title="Suggested drafts" subtitle="Generated from findings; hypotheses until the sandbox replay confirms them" id="suggestions">
          <ul className="grid gap-2 md:grid-cols-2">{sugg.data.suggestions.map((s) => (
            <li key={s.id} className="card-flat p-3 grid gap-1.5"><div className="flex gap-2 items-center"><Lozenge tone="violet">{s.rule_id}</Lozenge><b className="text-[13px]">{s.title}</b></div>
              <p className="text-xs text-muted">{s.rationale}</p><pre tabIndex={0} aria-label="Suggested SQL" className="mono m-0 text-[11px] overflow-auto scroll-thin max-h-28">{s.sql}</pre>
              <div><Button size="sm" onClick={() => { setDraft(s.sql); setLint(null); setWid(null); }}>Use as draft</Button></div></li>))}</ul>
        </Card>
      )}
      {w.data && base && <Card title="Result" subtitle={`Experiment ${w.data.id}`} id="result"><Results w={w.data} baselineRunId={base.id} /></Card>}
      {(hist.data?.length ?? 0) > 0 && (
        <Card title="Experiment history" id="whatif-history">
          <ul className="grid gap-1 text-[12px]">{hist.data!.slice(0, 8).map((h) => <li key={h.id} className="flex gap-3 flex-wrap"><span className="mono">{h.id.slice(0, 8)}</span><Lozenge tone={h.verdict === "improves" ? "teal" : "muted"}>{h.verdict || h.status}</Lozenge>
            <span className="text-muted">resolved {h.resolved_findings} · regressions {h.new_regressions}</span><button type="button" className="text-sky underline ml-auto" onClick={() => setWid(h.id)}>open</button></li>)}</ul>
        </Card>
      )}
    </div>
  );
}
