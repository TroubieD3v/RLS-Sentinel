import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import type {
  AuditEvent, CaseRow, ConnectionProfile, Finding, FixtureDetail, Fixture, GraphData, Health, HistoryRow, Matrix, RuleInfo, RunMeta, Snapshot,
  Suggestion, Suppression, WhatIf,
} from "@/api/types";
import { useApp } from "@/state/app";

export const qk = {
  health: ["health"], fixtures: ["fixtures"], runs: ["runs"], history: ["history"], rules: ["rules"], audit: ["audit"], suppressions: ["suppressions"],
  connections: ["connections"], whatifs: ["whatifs"],
};

export const useHealth = () => useQuery({ queryKey: qk.health, queryFn: async () => (await api<Health>("/health")).data, refetchInterval: 30000 });
export const useFixtures = () => useQuery({ queryKey: qk.fixtures, queryFn: async () => (await api<Fixture[]>("/fixtures")).data });
export const useFixture = (name: string | null) =>
  useQuery({ queryKey: ["fixture", name], enabled: !!name, queryFn: async () => (await api<FixtureDetail>(`/fixtures/${name}`)).data });
export const useRuns = () =>
  useQuery({
    queryKey: qk.runs,
    queryFn: async () => (await api<RunMeta[]>("/test-runs?limit=200")).data,
    refetchInterval: (q) => (q.state.data?.some((r) => r.status === "queued" || r.status === "running") ? 2000 : 15000),
  });
export const useHistory = () => useQuery({ queryKey: qk.history, queryFn: async () => (await api<HistoryRow[]>("/history?limit=200")).data });
export const useRules = () => useQuery({ queryKey: qk.rules, queryFn: async () => (await api<RuleInfo[]>("/rules")).data, staleTime: Infinity });
export const useConnections = () => useQuery({ queryKey: qk.connections, queryFn: async () => (await api<ConnectionProfile[]>("/connections")).data });
export const useAudit = () => useQuery({ queryKey: qk.audit, queryFn: async () => (await api<AuditEvent[]>("/audit?limit=100")).data });
export const useSuppressions = () => useQuery({ queryKey: qk.suppressions, queryFn: async () => (await api<Suppression[]>("/suppressions")).data });
export const useWhatIfs = () => useQuery({ queryKey: qk.whatifs, queryFn: async () => (await api<{ id: string; baseline_run_id: string; status: string; verdict: string; resolved_findings: number; new_regressions: number; created_at: string }[]>("/what-if")).data });
export const useWhatIf = (id: string | null) =>
  useQuery({
    queryKey: ["whatif", id], enabled: !!id,
    queryFn: async () => (await api<WhatIf>(`/what-if/${id}`)).data,
    refetchInterval: (q) => (q.state.data && (q.state.data.status === "queued" || q.state.data.status === "running") ? 1200 : false),
  });

/** The run every analysis page works on: explicitly selected, else the newest completed lab/catalog run. */
export function useActiveRun() {
  const { activeRunId } = useApp();
  const runs = useRuns();
  const list = runs.data ?? [];
  const chosen = list.find((r) => r.id === activeRunId) ?? list.find((r) => r.status === "completed" && r.kind !== "whatif_sandbox") ?? null;
  return { run: chosen, runs: list, isLoading: runs.isLoading, error: runs.error, refetch: runs.refetch };
}

export const useRunDetail = (id: string | null | undefined) =>
  useQuery({
    queryKey: ["run", id], enabled: !!id,
    queryFn: async () => (await api<RunMeta>(`/test-runs/${id}`)).data,
    refetchInterval: (q) => (q.state.data && (q.state.data.status === "queued" || q.state.data.status === "running") ? 1500 : false),
  });
export const useMatrix = (id: string | null | undefined) =>
  useQuery({ queryKey: ["matrix", id], enabled: !!id, queryFn: async () => (await api<Matrix>(`/test-runs/${id}/matrix`)).data });
export const useCases = (id: string | null | undefined) =>
  useQuery({ queryKey: ["cases", id], enabled: !!id, queryFn: async () => (await api<CaseRow[]>(`/test-runs/${id}/cases?limit=1000`)).data });
export const useSnapshot = (snapshotId: string | null | undefined) =>
  useQuery({ queryKey: ["snapshot", snapshotId], enabled: !!snapshotId, queryFn: async () => (await api<Snapshot>(`/scans/${snapshotId}/snapshot`)).data });
export const useRunGraph = (id: string | null | undefined, params: Record<string, string | number | undefined>) => {
  const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== "").map(([k, v]) => [k, String(v)])).toString();
  return useQuery({ queryKey: ["graph", id, qs], enabled: !!id, queryFn: async () => (await api<GraphData>(`/test-runs/${id}/graph?${qs}`)).data });
};
export const useFindings = (params: Record<string, string | number | boolean | undefined>) => {
  const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== "").map(([k, v]) => [k, String(v)])).toString();
  return useQuery({ queryKey: ["findings", qs], queryFn: async () => { const r = await api<Finding[]>(`/findings?${qs}`); return { items: r.data, total: r.meta.pagination?.total ?? r.data.length }; } });
};
export const useSuggestions = (id: string | null | undefined) =>
  useQuery({ queryKey: ["suggestions", id], enabled: !!id, queryFn: async () => (await api<{ suggestions: Suggestion[]; combined_sql: string; notice: string }>(`/test-runs/${id}/suggestions`)).data });
