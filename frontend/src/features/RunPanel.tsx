import { Play, Square } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Button, Field, Lozenge, ProgressBar, Select, StatusLozenge } from "@/design-system/ui";
import { useFixtures, useHealth } from "@/lib/queries";
import type { RunJobState } from "./useRunJob";

const OBS_TONE: Record<string, string> = { ROW_RETURNED: "tone-coral", ROWS_AFFECTED: "tone-coral", ROW_INSERTED: "tone-coral", NO_ROWS: "tone-violet", RLS_VIOLATION: "tone-violet", GRANT_DENIED: "tone-amber" };

export function FixturePicker({ fixture, variant, onChange }: { fixture: string; variant: string; onChange: (f: string, v: string) => void }) {
  const fx = useFixtures();
  const list = useMemo(() => fx.data ?? [], [fx.data]);
  const cur = list.find((f) => f.name === fixture);
  useEffect(() => { if (!fixture && list[0]) onChange(list[0].name, "vulnerable"); }, [fixture, list, onChange]);
  return (
    <div className="grid sm:grid-cols-2 gap-3">
      <Field label="Fixture (synthetic)" htmlFor="fx-pick" hint={cur?.description.slice(0, 160)}>
        <Select id="fx-pick" value={fixture} onChange={(e) => onChange(e.target.value, variant)} data-testid="fixture-select">
          {list.map((f) => <option key={f.name} value={f.name}>{f.title}</option>)}
        </Select>
      </Field>
      <Field label="Variant" htmlFor="fx-variant" hint="Run the vulnerable variant to see findings; the secure variant is the negative control.">
        <Select id="fx-variant" value={variant} onChange={(e) => onChange(fixture, e.target.value)} data-testid="variant-select">
          {(cur?.variants ?? ["vulnerable", "secure"]).map((v) => <option key={v} value={v}>{v}</option>)}
        </Select>
      </Field>
    </div>
  );
}

export function LiveRun({ state, onCancel }: { state: RunJobState; onCancel: () => void }) {
  const [tick, setTick] = useState(0);
  useEffect(() => { const t = setInterval(() => setTick((x) => x + 1), 1000); return () => clearInterval(t); }, []);
  void tick;
  const active = state.phase === "starting" || state.phase === "running";
  return (
    <div className="grid gap-3" data-testid="live-run" aria-live="polite">
      <div className="flex items-center gap-3 flex-wrap">
        <StatusLozenge status={state.phase === "starting" ? "queued" : state.phase === "idle" ? "queued" : state.phase === "running" ? "running" : state.phase} />
        <span className="text-[13px]" data-testid="live-stage">{state.stage ? <span className="mono text-muted">{state.stage} · </span> : null}{state.message}</span>
        {active && <Button size="sm" variant="danger" onClick={onCancel} data-testid="cancel-run"><Square size={12} aria-hidden /> Cancel</Button>}
      </div>
      <ProgressBar value={state.done} max={Math.max(state.total, 1)} label="Test cases executed" />
      <div className="text-xs text-muted mono" data-testid="live-count">{state.done} / {state.total} cases executed (real job events)</div>
      {state.cases.length > 0 && (
        <ul tabIndex={0} className="card-flat max-h-40 overflow-auto scroll-thin p-2 mono text-xs grid gap-0.5" aria-label="Observed cases">
          {state.cases.slice(-40).map((c) => (
            <li key={`${c.n}-${c.case}`} className="flex gap-2"><span className="text-muted w-8 text-right">{c.n}</span><span className="truncate">{c.case}</span>
              <span className={`ml-auto ${OBS_TONE[c.observed] ?? "tone-muted"}`}>{c.observed}</span></li>
          ))}
        </ul>
      )}
      {state.error && <div role="alert" className="tone-coral text-[13px]">{state.error}</div>}
    </div>
  );
}

export function RunButton({ onClick, busy, disabled }: { onClick: () => void; busy: boolean; disabled?: boolean }) {
  const health = useHealth();
  const unavailable = health.data && !health.data.lab.available;
  return (
    <div className="flex items-center gap-3 flex-wrap">
      <Button variant="primary" onClick={onClick} loading={busy} disabled={disabled || !!unavailable} data-testid="run-tests"><Play size={14} aria-hidden /> Run verification</Button>
      {unavailable && <Lozenge tone="coral">No disposable PostgreSQL available</Lozenge>}
      <span className="text-xs text-muted">Executes in a disposable database. Your source databases are never written to.</span>
    </div>
  );
}
