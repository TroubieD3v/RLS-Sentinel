import { useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, FileCode2, RotateCcw } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "@/api/client";
import type { CaseRow, SpecValidation } from "@/api/types";
import { describeError, PageHeader } from "@/components/Shell";
import { Button, Card, EmptyState, Field, Input, Lozenge, Select, StatusLozenge, Terminal } from "@/design-system/ui";
import { FixturePicker, LiveRun, RunButton } from "@/features/RunPanel";
import { useRunJob } from "@/features/useRunJob";
import { useCases, useFixture } from "@/lib/queries";
import { useApp } from "@/state/app";

const OPS = ["SELECT", "INSERT", "UPDATE", "DELETE", "UPSERT"] as const;

function Editor({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const lines = value.split("\n").length;
  return (
    <div className="flex card-flat overflow-hidden h-[460px]">
      <div aria-hidden className="mono text-right text-muted select-none py-2 pl-3 pr-2 border-r border-line overflow-hidden bg-raised" style={{ lineHeight: "1.5" }}>
        {Array.from({ length: Math.min(lines, 999) }, (_, i) => <div key={i}>{i + 1}</div>)}
      </div>
      <textarea
        aria-label="Expected-policy specification (YAML or JSON)" data-testid="spec-editor" spellCheck={false} value={value} onChange={(e) => onChange(e.target.value)}
        className="mono flex-1 bg-transparent p-2 outline-none resize-none scroll-thin whitespace-pre overflow-auto" style={{ lineHeight: "1.5", tabSize: 2 }}
      />
    </div>
  );
}

function Paired({ cases }: { cases: CaseRow[] }) {
  const resources = useMemo(() => Array.from(new Set(cases.filter((c) => c.resource).map((c) => c.resource as string))), [cases]);
  const [res, setRes] = useState("");
  const cur = res || resources[0] || "";
  const forRes = cases.filter((c) => c.resource === cur);
  const baseline = forRes.filter((c) => c.expected === "ALLOW");
  const cross = forRes.filter((c) => c.expected !== "ALLOW");
  const col = (title: string, tone: string, list: CaseRow[]) => (
    <div className="card-flat p-3 grid gap-2 content-start">
      <h4 className={`text-xs font-bold uppercase tracking-wide ${tone}`}>{title}</h4>
      {list.length === 0 && <p className="text-xs text-muted">No case.</p>}
      {list.map((c) => (
        <div key={c.case_id} className="text-[12px] border-t border-line pt-2 first:border-0 first:pt-0">
          <div className="flex gap-2 items-center flex-wrap"><StatusLozenge status={c.status} /><b className="mono">{c.actor}</b><span className="text-muted">{c.operation}</span></div>
          <div className="mono text-muted mt-0.5">expected {c.expected} · observed {c.observed}{c.sqlstate ? ` (${c.sqlstate})` : ""} · gate {c.evidence.raw.gate}</div>
        </div>
      ))}
    </div>
  );
  return (
    <Card title="Baseline vs cross-identity" subtitle="Authorized control next to the cross-identity attempt for the same resource" id="paired">
      <Field label="Resource" htmlFor="pair-res"><Select id="pair-res" value={cur} onChange={(e) => setRes(e.target.value)}>{resources.map((r) => <option key={r}>{r}</option>)}</Select></Field>
      <div className="grid md:grid-cols-2 gap-3 mt-3">{col("Authorized baseline (expected ALLOW)", "tone-teal", baseline)}{col("Cross-identity (expected DENY / NO_ROWS / ERROR)", "tone-coral", cross)}</div>
    </Card>
  );
}

export default function TestStudio() {
  const [fx, setFx] = useState({ fixture: "", variant: "vulnerable" });
  const fixture = useFixture(fx.fixture || null);
  const [text, setText] = useState("");
  const [filename, setFilename] = useState("sentinel.yaml");
  const [val, setVal] = useState<SpecValidation | null>(null);
  const [busyVal, setBusyVal] = useState(false);
  const job = useRunJob();
  const qc = useQueryClient();
  const { toast } = useApp();
  const runId = job.state.runId;
  const cases = useCases(job.state.phase === "completed" ? runId : null);
  const busy = job.state.phase === "starting" || job.state.phase === "running";
  const [form, setForm] = useState({ id: "", actor: "", operation: "SELECT", resource: "", expected: "DENY", deny_gate: "rls" });

  const loadedKey = useRef("");
  useEffect(() => { // load the fixture's own independent spec once per fixture/variant; never overwrite the user's edits on refetch
    const s = fixture.data?.specs[fx.variant];
    const key = `${fx.fixture}:${fx.variant}`;
    if (s && loadedKey.current !== key) { loadedKey.current = key; setText(s); setFilename("sentinel.yaml"); setVal(null); }
  }, [fixture.data, fx.fixture, fx.variant]);

  const validate = async () => {
    setBusyVal(true);
    try { setVal((await api<SpecValidation>("/expectations/validate", { method: "POST", body: { spec: text, filename } })).data); }
    catch (e) { toast("coral", describeError(e)); } finally { setBusyVal(false); }
  };
  const failed = (cases.data ?? []).filter((c) => c.status === "FAIL").map((c) => c.case_id);
  const n = val?.normalized;

  const addExpectation = () => {
    if (!n) return;
    const e: Record<string, unknown> = { id: form.id.trim(), actor: form.actor, operation: form.operation, expected: form.expected, resource: form.resource || undefined };
    if (form.expected === "DENY") e.deny_gate = form.deny_gate;
    const next = { ...n, expectations: [...n.expectations, e] };
    setText(JSON.stringify(next, null, 2)); setFilename("sentinel.json"); setVal(null);
    toast("blue", "Expectation added; the editor now holds the equivalent JSON form of the spec.");
    setForm({ ...form, id: "" });
  };

  return (
    <div className="grid gap-4">
      <PageHeader kicker="Expected policy → executable tests" title="Test Studio"
        subtitle="The spec states what SHOULD be allowed or denied, independently of the database. The harness executes it as genuinely different roles in a disposable PostgreSQL and compares." />
      <div className="grid xl:grid-cols-[1.25fr_1fr] gap-4 items-start">
        <Card title="Expected-policy specification" subtitle="YAML or JSON; validated with Pydantic; raw SQL is rejected" id="editor"
          actions={<Lozenge tone="violet" icon={<FileCode2 size={12} aria-hidden />}>{filename}</Lozenge>}>
          <div className="grid gap-3">
            <FixturePicker fixture={fx.fixture} variant={fx.variant} onChange={(f, v) => setFx({ fixture: f, variant: v })} />
            <Editor value={text} onChange={(v) => { setText(v); setVal(null); }} />
            <div className="flex gap-2 flex-wrap items-center">
              <Button onClick={() => void validate()} loading={busyVal} data-testid="validate-spec"><CheckCircle2 size={14} aria-hidden /> Dry-run validation</Button>
              <Button variant="ghost" onClick={() => { const s = fixture.data?.specs[fx.variant]; if (s) { setText(s); setVal(null); } }}><RotateCcw size={14} aria-hidden /> Reset to fixture spec</Button>
            </div>
            {val && (
              <div role="status" data-testid="validation-result" className="card-flat p-3 grid gap-2">
                <div className="flex gap-2 items-center">{val.valid ? <Lozenge tone="teal">Valid</Lozenge> : <Lozenge tone="coral">Invalid</Lozenge>}
                  {val.counts && <span className="text-xs text-muted mono">{val.counts.actors} actors · {val.counts.resources} resources · {val.counts.expectations} expectations · {val.counts.privileges} privilege checks</span>}</div>
                {val.checksum && <p className="mono text-xs text-muted break-all">{val.checksum}</p>}
                <ul className="grid gap-1 text-[12px]">{val.issues.map((i, k) => <li key={k}><span className={i.level === "error" ? "tone-coral font-bold" : "tone-amber font-bold"}>{i.level}</span> <span className="mono">{i.path}</span> {i.message}</li>)}</ul>
              </div>
            )}
            <RunButton busy={busy} disabled={!fx.fixture || !text} onClick={() => void job.start({ fixture: fx.fixture, variant: fx.variant, spec: text, filename })} />
            {job.state.phase !== "idle" && <LiveRun state={job.state} onCancel={() => void job.cancel()} />}
            {job.state.phase === "completed" && (
              <div className="flex gap-2 flex-wrap items-center" data-testid="run-done">
                <Link to="/matrix"><Button variant="primary">Open matrix</Button></Link><Link to="/findings"><Button>Review findings</Button></Link>
                {failed.length > 0 && <Button onClick={() => void job.start({ fixture: fx.fixture, variant: fx.variant, spec: text, filename, only: failed }).then(() => qc.invalidateQueries())}>Rerun {failed.length} failed</Button>}
              </div>
            )}
          </div>
        </Card>
        <div className="grid gap-4">
          <Card title="Form view" subtitle="Structured equivalent of the validated spec" id="form-view">
            {!n ? <p className="text-[13px] text-muted">Run the dry-run validation to see the form view of this spec.</p> : (
              <div className="grid gap-3 text-[12px]">
                <div><h4 className="font-bold text-xs uppercase tracking-wide text-muted mb-1">Actors</h4>
                  <ul className="grid gap-1">{n.actors.map((a) => <li key={a.id} className="mono card-flat px-2 py-1">{a.id} → {a.pg_role} {a.tenant ? `· tenant ${a.tenant}` : ""} · {a.kind}</li>)}</ul></div>
                <div><h4 className="font-bold text-xs uppercase tracking-wide text-muted mb-1">Resources</h4>
                  <ul className="grid gap-1">{n.resources.map((r) => <li key={r.id} className="mono card-flat px-2 py-1">{r.id} · {r.table}</li>)}</ul></div>
                <div><h4 className="font-bold text-xs uppercase tracking-wide text-muted mb-1">Expectations ({n.expectations.length})</h4>
                  <div tabIndex={0} role="region" aria-label="Generated expectations" className="max-h-52 overflow-auto scroll-thin card-flat"><table className="w-full"><tbody>{n.expectations.map((e) => (
                    <tr key={e.id} className="border-t border-line first:border-0"><td className="p-1.5 mono">{e.id}</td><td className="p-1.5">{e.actor}</td><td className="p-1.5">{e.operation}</td><td className="p-1.5 font-bold">{e.expected}</td></tr>))}</tbody></table></div></div>
                <form className="card-flat p-3 grid gap-2" onSubmit={(e) => { e.preventDefault(); addExpectation(); }} aria-label="Add expectation">
                  <h4 className="font-bold text-xs uppercase tracking-wide text-muted">Add expectation</h4>
                  <div className="grid grid-cols-2 gap-2">
                    <Field label="Id" htmlFor="f-id"><Input id="f-id" value={form.id} onChange={(e) => setForm({ ...form, id: e.target.value })} placeholder="bob-cannot-read-x" pattern="[A-Za-z0-9_.:\-]+" /></Field>
                    <Field label="Actor" htmlFor="f-actor"><Select id="f-actor" value={form.actor} onChange={(e) => setForm({ ...form, actor: e.target.value })}><option value="" />{n.actors.map((a) => <option key={a.id}>{a.id}</option>)}</Select></Field>
                    <Field label="Operation" htmlFor="f-op"><Select id="f-op" value={form.operation} onChange={(e) => setForm({ ...form, operation: e.target.value })}>{OPS.map((o) => <option key={o}>{o}</option>)}</Select></Field>
                    <Field label="Resource" htmlFor="f-res"><Select id="f-res" value={form.resource} onChange={(e) => setForm({ ...form, resource: e.target.value })}><option value="" />{n.resources.map((r) => <option key={r.id}>{r.id}</option>)}</Select></Field>
                    <Field label="Expected" htmlFor="f-exp"><Select id="f-exp" value={form.expected} onChange={(e) => setForm({ ...form, expected: e.target.value })}>{["ALLOW", "DENY", "NO_ROWS"].map((o) => <option key={o}>{o}</option>)}</Select></Field>
                    <Field label="Deny gate" htmlFor="f-gate" hint="rls · grant · any"><Select id="f-gate" value={form.deny_gate} onChange={(e) => setForm({ ...form, deny_gate: e.target.value })}>{["rls", "grant", "any"].map((o) => <option key={o}>{o}</option>)}</Select></Field>
                  </div>
                  <Button type="submit" size="sm" disabled={!form.id.trim() || !form.actor || !form.resource}>Add to spec (as JSON)</Button>
                </form>
              </div>
            )}
          </Card>
          <Card title="CLI equivalent" id="cli">
            <Terminal title="same run from a terminal" lines={[`rls-sentinel spec validate ./sentinel.yaml`, `rls-sentinel test --fixture ${fx.fixture || "<fixture>"} --variant ${fx.variant} --format json -o results/test-run.json`, `rls-sentinel report results/test-run.json --format sarif -o results/findings.sarif`]} />
          </Card>
        </div>
      </div>
      {cases.data && cases.data.length > 0 && <Paired cases={cases.data} />}
      {job.state.phase === "idle" && <EmptyState title="Nothing executed yet">Choose a fixture, validate the spec, then run. Progress below is streamed from real job events.</EmptyState>}
    </div>
  );
}
