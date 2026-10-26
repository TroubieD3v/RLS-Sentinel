import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, streamEvents } from "@/api/client";
import { qk } from "@/lib/queries";
import { useApp } from "@/state/app";

export interface LiveCase { case: string; observed: string; n: number }
export interface RunJobState {
  phase: "idle" | "starting" | "running" | "completed" | "failed" | "cancelled";
  runId: string | null; jobId: string | null; stage: string; message: string; done: number; total: number; cases: LiveCase[]; error: string | null;
}
const IDLE: RunJobState = { phase: "idle", runId: null, jobId: null, stage: "", message: "", done: 0, total: 0, cases: [], error: null };

export interface StartArgs { fixture: string; variant: string; spec?: string; filename?: string; only?: string[] }

/** Starts a lab run and mirrors REAL job events (stage / done / total / per-case observations). Nothing here is simulated. */
export function useRunJob() {
  const [state, setState] = useState<RunJobState>(IDLE);
  const abort = useRef<AbortController | null>(null);
  const qc = useQueryClient();
  const { setActiveRunId, toast } = useApp();

  useEffect(() => () => abort.current?.abort(), []);

  const start = useCallback(async (args: StartArgs) => {
    abort.current?.abort();
    const ac = new AbortController();
    abort.current = ac;
    setState({ ...IDLE, phase: "starting", message: "Submitting run…" });
    try {
      const r = await api<{ run_id: string; job_id: string; total_cases: number }>("/test-runs", { method: "POST", body: args });
      const { run_id, job_id, total_cases } = r.data;
      setState({ ...IDLE, phase: "running", runId: run_id, jobId: job_id, total: total_cases, message: "Queued" });
      void qc.invalidateQueries({ queryKey: qk.runs });
      await streamEvents(`/jobs/${job_id}/events`, (e) => {
        setState((s) => {
          if (e.type === "progress") {
            const d = e.data as { stage?: string; message?: string; done?: number; total?: number; case?: string; observed?: string };
            const cases = d.case ? [...s.cases.slice(-199), { case: d.case, observed: d.observed ?? "", n: d.done ?? s.cases.length + 1 }] : s.cases;
            return { ...s, stage: d.stage ?? s.stage, message: d.message ?? s.message, done: d.done ?? s.done, total: d.total ?? s.total, cases };
          }
          if (e.type === "completed") return { ...s, phase: "completed", message: "Run completed" };
          if (e.type === "failed") return { ...s, phase: "failed", error: String(e.data.error ?? "Run failed"), message: "Run failed" };
          if (e.type === "cancelled") return { ...s, phase: "cancelled", message: "Run cancelled" };
          return s;
        });
      }, ac.signal);
      await qc.invalidateQueries({ queryKey: qk.runs });
      await qc.invalidateQueries({ queryKey: qk.history });
      await qc.invalidateQueries({ queryKey: ["findings"] });
      setActiveRunId(run_id);
    } catch (e) {
      if ((e as Error).name === "AbortError") return;
      const msg = e instanceof Error ? e.message : "Run failed";
      setState((s) => ({ ...s, phase: "failed", error: msg, message: msg }));
      toast("coral", msg);
    }
  }, [qc, setActiveRunId, toast]);

  const cancel = useCallback(async () => {
    if (state.jobId) {
      try { await api(`/jobs/${state.jobId}/cancel`, { method: "POST" }); } catch (e) { toast("coral", e instanceof Error ? e.message : "Cancel failed"); }
    }
  }, [state.jobId, toast]);

  const reset = useCallback(() => { abort.current?.abort(); setState(IDLE); }, []);
  return { state, start, cancel, reset };
}
