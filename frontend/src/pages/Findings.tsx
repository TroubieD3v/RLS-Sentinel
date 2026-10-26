import { useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { ExternalLink, EyeOff, Wand2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "@/api/client";
import type { Finding, Lifecycle } from "@/api/types";
import { describeError, PageHeader } from "@/components/Shell";
import {
  Button, Card, Dialog, EmptyState, ErrorState, EvidenceLozenge, Field, Input, Lozenge, ProvenanceLozenge, Select, SeverityLozenge, Skeleton, Terminal,
} from "@/design-system/ui";
import { CaseDetail } from "@/features/CaseDetail";
import { useActiveRun, useCases, useFindings, useRules, useSuggestions } from "@/lib/queries";
import { Sql } from "@/lib/sql";
import { useApp } from "@/state/app";

const LIFECYCLE: Lifecycle[] = ["open", "triaged", "accepted_risk", "false_positive", "fixed", "needs_info"];
const LIFE_LABEL: Record<string, string> = { open: "Open", triaged: "Triaged", accepted_risk: "Accepted risk", false_positive: "False positive", fixed: "Fixed", needs_info: "Needs more information" };

function EvidenceLine({ f }: { f: Finding }) {
  const o = f.objects as Record<string, unknown>;
  const steps: { label: string; value: string; kind: string }[] = [{ kind: "finding", label: "Finding", value: `${f.rule_id} · ${f.subject}` }];
  if (o.policy || (Array.isArray(o.applicable_policies) && o.applicable_policies.length)) {
    const names = o.policy ? [String(o.policy)] : (o.applicable_policies as string[]);
    steps.push({ kind: "policy", label: "SQL policy", value: `${names.join(", ")}${o.table ? ` on ${String(o.table)}` : ""}` });
  } else if (o.table) steps.push({ kind: "object", label: "Resource", value: String(o.table) });
  if (o.role || o.actor) steps.push({ kind: "role", label: "Effective role", value: `${String(o.role ?? "")}${o.actor ? ` (actor ${String(o.actor)})` : ""}${o.bypass_reason ? ` · bypass ${String(o.bypass_reason)}` : ""}` });
  for (const e of f.evidence.filter((x) => x.kind === "case")) steps.push({ kind: "case", label: "Test result", value: e.summary });
  if (!f.evidence.some((x) => x.kind === "case")) for (const e of f.evidence.slice(0, 2)) steps.push({ kind: e.kind, label: e.kind === "catalog" ? "Catalog fact" : "Evidence", value: e.summary });
  return (
    <ol className="evidence-line grid gap-0.5 list-none m-0" aria-label="Evidence lineage" data-testid="evidence-line">
      {steps.map((s, i) => (
        <li key={i}><div className="text-[10px] uppercase tracking-widest text-muted">{s.label}</div><div className="mono break-words text-[12px]">{s.value}</div></li>
      ))}
    </ol>
  );
}

function SuppressDialog({ f, open, onOpenChange }: { f: Finding; open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient();
  const { toast } = useApp();
  const [scope, setScope] = useState(f.subject.split("#")[0] || "*");
  const [reason, setReason] = useState("");
  const [owner, setOwner] = useState("");
  const [reviewer, setReviewer] = useState("");
  const [days, setDays] = useState(30);
  const [busy, setBusy] = useState(false);
  const valid = reason.trim().length >= 10 && owner.trim() && reviewer.trim() && days >= 1 && days <= 365;
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title={`Suppress ${f.rule_id}`} description="Hides matching findings from normal views. The underlying result is never modified, and the decision is audit-logged.">
      <form className="grid gap-3" onSubmit={(e) => {
        e.preventDefault();
        setBusy(true);
        api("/suppressions", { method: "POST", body: { rule_id: f.rule_id, scope, reason, owner, reviewer, expires_at: new Date(Date.now() + days * 864e5).toISOString() } })
          .then(() => { toast("teal", "Suppression recorded (audited)."); void qc.invalidateQueries(); onOpenChange(false); })
          .catch((err) => toast("coral", describeError(err))).finally(() => setBusy(false));
      }}>
        <Field label="Scope (subject prefix, or *)" htmlFor="sup-scope"><Input id="sup-scope" value={scope} onChange={(e) => setScope(e.target.value)} /></Field>
        <Field label="Reason (min 10 characters)" htmlFor="sup-reason"><Input id="sup-reason" value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Owner" htmlFor="sup-owner"><Input id="sup-owner" value={owner} onChange={(e) => setOwner(e.target.value)} /></Field>
          <Field label="Reviewer" htmlFor="sup-rev"><Input id="sup-rev" value={reviewer} onChange={(e) => setReviewer(e.target.value)} /></Field>
        </div>
        <Field label="Expires in (days, max 365)" htmlFor="sup-days"><Input id="sup-days" type="number" min={1} max={365} value={days} onChange={(e) => setDays(Number(e.target.value))} /></Field>
        <Button variant="primary" type="submit" disabled={!valid} loading={busy}>Create suppression</Button>
      </form>
    </Dialog>
  );
}

function Detail({ f, runId }: { f: Finding; runId: string }) {
  const qc = useQueryClient();
  const { toast } = useApp();
  const rules = useRules();
  const cases = useCases(runId);
  const sugg = useSuggestions(runId);
  const [state, setState] = useState<Lifecycle>(f.lifecycle_state);
  const [note, setNote] = useState(f.reviewer_note);
  const [busy, setBusy] = useState(false);
  const [sup, setSup] = useState(false);
  useEffect(() => { setState(f.lifecycle_state); setNote(f.reviewer_note); }, [f.id, f.lifecycle_state, f.reviewer_note]);
  const rule = rules.data?.find((r) => r.id === f.rule_id);
  const relCase = (cases.data ?? []).find((c) => f.case_ids.includes(c.case_id));
  const fixes = (sugg.data?.suggestions ?? []).filter((s) => s.finding_ids.includes(f.id));
  const prov = f.provenance.includes("RUNTIME_OBSERVATION") ? "runtime" : f.provenance.includes("STATIC_INFERENCE") ? "static" : f.provenance.includes("CATALOG_FACT") ? "catalog" : "insufficient";
  return (
    <article className="grid gap-4" data-testid="finding-detail" aria-label={`Finding ${f.rule_id}`}>
      <header className="grid gap-2">
        <div className="flex gap-2 flex-wrap items-center"><EvidenceLozenge cls={f.evidence_class} /><SeverityLozenge severity={f.severity} /><ProvenanceLozenge kind={prov} />
          {f.suppressed && <Lozenge tone="muted" icon={<EyeOff size={12} aria-hidden />}>Suppressed</Lozenge>}</div>
        <h2 className="text-lg font-bold leading-snug">{f.rule_id} · {f.title}</h2>
        <p className="text-xs text-muted">Severity rationale: {f.severity_rationale}</p>
      </header>
      <section aria-label="What happened"><h3 className="text-xs font-bold uppercase tracking-wide text-muted mb-1">What happened</h3><p>{f.summary}</p></section>
      {f.why_it_matters && <section aria-label="Why it matters"><h3 className="text-xs font-bold uppercase tracking-wide text-muted mb-1">Why it matters</h3><p>{f.why_it_matters}</p></section>}
      {(f.expected || f.observed) && (
        <section className="grid grid-cols-2 gap-3" aria-label="Expected and observed">
          <div className="card-flat p-3"><div className="text-xs uppercase text-muted font-bold">Expected (independent spec)</div><div className="mono mt-1">{f.expected ?? "—"}</div></div>
          <div className="card-flat p-3"><div className="text-xs uppercase text-muted font-bold">Observed</div><div className="mono mt-1 break-words">{f.observed ?? "—"}</div></div>
        </section>
      )}
      <section aria-label="Evidence"><h3 className="text-xs font-bold uppercase tracking-wide text-muted mb-2">Evidence line</h3><EvidenceLine f={f} />
        {f.location && <p className="text-xs text-muted mt-2">Source: <span className="mono">{f.location.path}{f.location.line ? `:${f.location.line}` : ""}</span></p>}</section>
      {relCase && <section aria-label="Executed test case"><h3 className="text-xs font-bold uppercase tracking-wide text-muted mb-2">Executed test case</h3><div className="card-flat p-3"><CaseDetail c={relCase} /></div></section>}
      {f.reproduction.length > 0 && <section aria-label="Steps to reproduce"><h3 className="text-xs font-bold uppercase tracking-wide text-muted mb-1">Steps to reproduce (disposable fixture)</h3><Terminal title="reproduce" lines={f.reproduction} /></section>}
      <section aria-label="Remediation"><h3 className="text-xs font-bold uppercase tracking-wide text-muted mb-1">Suggested remediation</h3><p>{f.remediation || rule?.remediation}</p>
        <p className="text-xs text-muted mt-1">Suggestions are hypotheses. They are verified only by replaying them in a disposable clone — never applied automatically.</p>
        {fixes.map((s) => (
          <div key={s.id} className="mt-2 card-flat p-3 grid gap-2">
            <div className="font-semibold text-[13px]">{s.title}</div><div className="text-xs text-muted">{s.rationale}</div>
            <pre className="m-0 mono overflow-auto scroll-thin"><Sql text={s.sql} /></pre>
            <ul className="text-xs text-muted list-disc pl-4">{s.caveats.map((c) => <li key={c}>{c}</li>)}</ul>
            <div><Link to={`/what-if?draft=${encodeURIComponent(s.sql)}`}><Button size="sm"><Wand2 size={13} aria-hidden /> Test in What-if Lab</Button></Link></div>
          </div>
        ))}
      </section>
      <section aria-label="Limitations" className="card-flat p-3"><h3 className="text-xs font-bold uppercase tracking-wide text-muted mb-1">Limitations</h3><p className="text-[13px]">{f.limitations || "None recorded."}</p></section>
      {f.references.length > 0 && <ul className="flex gap-3 flex-wrap text-xs">{f.references.map((u) => <li key={u}><a href={u} target="_blank" rel="noreferrer noopener" className="text-sky underline inline-flex items-center gap-1">PostgreSQL / vendor docs <ExternalLink size={11} aria-hidden /></a></li>)}</ul>}
      <section aria-label="Review" className="card-flat p-3 grid gap-3">
        <h3 className="text-xs font-bold uppercase tracking-wide text-muted">Review workflow</h3>
        <div className="grid sm:grid-cols-[200px_1fr] gap-3">
          <Field label="State" htmlFor="rv-state"><Select id="rv-state" value={state} onChange={(e) => setState(e.target.value as Lifecycle)} data-testid="review-state">{LIFECYCLE.map((l) => <option key={l} value={l}>{LIFE_LABEL[l]}</option>)}</Select></Field>
          <Field label="Reviewer note" htmlFor="rv-note"><Input id="rv-note" value={note} onChange={(e) => setNote(e.target.value)} maxLength={4000} /></Field>
        </div>
        <div className="flex gap-2 flex-wrap">
          <Button variant="primary" loading={busy} data-testid="review-save" onClick={() => {
            setBusy(true);
            api(`/findings/${f.id}`, { method: "PATCH", body: { lifecycle_state: state, reviewer_note: note } })
              .then(() => { toast("teal", `Marked as ${LIFE_LABEL[state]}.`); void qc.invalidateQueries({ queryKey: ["findings"] }); })
              .catch((e) => toast("coral", describeError(e))).finally(() => setBusy(false));
          }}>Save review</Button>
          <Button onClick={() => setSup(true)}><EyeOff size={14} aria-hidden /> Suppress…</Button>
        </div>
      </section>
      <SuppressDialog f={f} open={sup} onOpenChange={setSup} />
    </article>
  );
}

export default function FindingsPage() {
  const { run, isLoading, error } = useActiveRun();
  const [sp, setSp] = useSearchParams();
  const [cls, setCls] = useState("");
  const [sev, setSev] = useState("");
  const [rule, setRule] = useState("");
  const [life, setLife] = useState("");
  const [q, setQ] = useState("");
  const [showSup, setShowSup] = useState(false);
  const rules = useRules();
  const list = useFindings({ run_id: run?.id, evidence_class: cls, severity: sev, rule_id: rule, lifecycle: life, q, include_suppressed: showSup || undefined, limit: 300 });
  const selId = sp.get("id");
  const items = useMemo(() => list.data?.items ?? [], [list.data]);
  const sel = useMemo(() => items.find((f) => f.id === selId) ?? null, [items, selId]);
  const grouped = useMemo(() => {
    const g: Record<string, Finding[]> = { CONFIRMED_VIOLATION: [], CONFIGURATION_RISK: [], INCONCLUSIVE: [] };
    for (const f of items) (g[f.evidence_class] ??= []).push(f);
    return g;
  }, [items]);
  const GROUP_TITLE: Record<string, string> = { CONFIRMED_VIOLATION: "Confirmed (runtime-proven)", CONFIGURATION_RISK: "Static configuration risks", INCONCLUSIVE: "Inconclusive / coverage" };

  if (isLoading) return <Skeleton className="h-96" />;
  if (error) return <ErrorState error={error} />;
  if (!run) return <EmptyState title="No findings yet">Run a verification first. Findings link every claim to its evidence.</EmptyState>;
  return (
    <div className="grid gap-4">
      <PageHeader kicker="Findings & evidence" title="Findings" subtitle="Confirmed violations are runtime-proven; static risks are hypotheses from catalog metadata; inconclusive items are unknown, never safe." />
      <Card>
        <div className="flex flex-wrap gap-3 items-end">
          <label className="grid gap-1 text-xs text-muted">Evidence<Select aria-label="Evidence class" value={cls} onChange={(e) => setCls(e.target.value)} className="w-52">
            <option value="">All</option><option value="CONFIRMED_VIOLATION">Confirmed violation</option><option value="CONFIGURATION_RISK">Configuration risk</option><option value="INCONCLUSIVE">Inconclusive</option></Select></label>
          <label className="grid gap-1 text-xs text-muted">Severity<Select aria-label="Severity" value={sev} onChange={(e) => setSev(e.target.value)} className="w-40">
            <option value="">All</option>{["Critical", "High", "Medium", "Low", "Informational", "Needs triage"].map((s) => <option key={s}>{s}</option>)}</Select></label>
          <label className="grid gap-1 text-xs text-muted">Rule<Select aria-label="Rule" value={rule} onChange={(e) => setRule(e.target.value)} className="w-52">
            <option value="">All rules</option>{(rules.data ?? []).map((r) => <option key={r.id} value={r.id}>{r.id} · {r.title.slice(0, 28)}</option>)}</Select></label>
          <label className="grid gap-1 text-xs text-muted">Review<Select aria-label="Lifecycle" value={life} onChange={(e) => setLife(e.target.value)} className="w-44">
            <option value="">Any</option>{LIFECYCLE.map((l) => <option key={l} value={l}>{LIFE_LABEL[l]}</option>)}</Select></label>
          <label className="grid gap-1 text-xs text-muted grow max-w-xs">Search<Input aria-label="Search findings" value={q} onChange={(e) => setQ(e.target.value)} placeholder="table, role, policy…" /></label>
          <label className="flex items-center gap-2 text-xs text-muted h-9"><input type="checkbox" checked={showSup} onChange={(e) => setShowSup(e.target.checked)} />show suppressed</label>
          <span className="ml-auto text-xs text-muted mono" data-testid="findings-count">{list.data?.total ?? 0} findings</span>
        </div>
      </Card>
      <div className="grid xl:grid-cols-[minmax(340px,480px)_1fr] gap-4 items-start">
        <div className="grid gap-3" data-testid="findings-list">
          {list.isLoading && <Skeleton className="h-64" />}
          {list.error && <ErrorState error={list.error} />}
          {!list.isLoading && items.length === 0 && <EmptyState title="No findings match">Zero findings is not proof of safety — check the coverage card on the Overview.</EmptyState>}
          {Object.entries(grouped).filter(([, v]) => v.length).map(([k, v]) => (
            <section key={k} aria-label={GROUP_TITLE[k]}>
              <h2 className="text-[11px] font-bold tracking-[0.14em] uppercase text-muted mb-1.5">{GROUP_TITLE[k] ?? k} · {v.length}</h2>
              <ul className="grid gap-1.5">
                {v.map((f) => (
                  <li key={f.id}>
                    <button type="button" onClick={() => setSp({ id: f.id })} data-testid="finding-row" aria-current={f.id === selId}
                      className={clsx("t-fast w-full text-left card-flat p-2.5 grid gap-1 hover:bg-hover", f.id === selId && "ring-2 ring-[var(--blue)]")}>
                      <div className="flex items-center gap-2 flex-wrap"><SeverityLozenge severity={f.severity} /><span className="mono font-bold text-[12px]">{f.rule_id}</span>
                        <span className="text-[10px] uppercase tracking-wider text-muted">{LIFE_LABEL[f.lifecycle_state]}</span></div>
                      <div className="text-[13px] font-medium line-clamp-2">{f.summary}</div>
                      <div className="mono text-[11px] text-muted truncate">{f.subject}</div>
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
        <Card className="min-h-64">{sel ? <Detail f={sel} runId={run.id} /> : <EmptyState title="Select a finding">Each finding shows what happened, expected vs observed, the evidence line down to the executed test, reproduction steps and limitations.</EmptyState>}</Card>
      </div>
    </div>
  );
}
