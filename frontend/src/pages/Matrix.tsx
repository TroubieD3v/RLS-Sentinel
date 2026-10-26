import clsx from "clsx";
import { Check, CircleHelp, Download, Ban, X } from "lucide-react";
import { useCallback, useMemo, useRef, useState, type KeyboardEvent, type ReactElement } from "react";
import type { Matrix, MatrixCell } from "@/api/types";
import { PageHeader } from "@/components/Shell";
import { Card, EmptyState, ErrorState, Input, Select, Skeleton } from "@/design-system/ui";
import { CaseDetail } from "@/features/CaseDetail";
import { useActiveRun, useCases, useFindings, useMatrix } from "@/lib/queries";
import { download } from "@/api/client";
import { Button } from "@/design-system/ui";
import { useApp } from "@/state/app";

const COL_W = 168;
const ROW_H = 46;
const OVERSCAN = 3;

const STATE_UI: Record<string, { glyph: ReactElement; text: string; cls: string }> = {
  ALLOW_VERIFIED: { glyph: <Check size={13} aria-hidden />, text: "ALLOW", cls: "tone-teal" },
  DENY_VERIFIED: { glyph: <Ban size={13} aria-hidden />, text: "DENY", cls: "tone-violet" },
  FAIL: { glyph: <X size={13} aria-hidden />, text: "FAIL", cls: "tone-coral font-bold" },
  UNKNOWN: { glyph: <CircleHelp size={13} aria-hidden />, text: "UNKNOWN", cls: "tone-amber" },
  EXPECTED_ALLOW: { glyph: <Check size={13} aria-hidden />, text: "expect allow", cls: "tone-muted" },
  EXPECTED_DENY: { glyph: <Ban size={13} aria-hidden />, text: "expect deny", cls: "tone-muted" },
};

function Legend({ totals }: { totals: Matrix["totals"] }) {
  return (
    <ul className="flex flex-wrap gap-x-5 gap-y-1 text-xs" aria-label="Matrix legend">
      {Object.entries(STATE_UI).filter(([k]) => k in totals || k.startsWith("ALLOW") || k.startsWith("DENY") || k === "FAIL").slice(0, 5).map(([k, u]) => (
        <li key={k} className={clsx("inline-flex items-center gap-1.5", u.cls)}>{u.glyph}<span className="text-ink">{u.text}</span><span className="text-muted mono">{totals[k] ?? 0}</span></li>
      ))}
    </ul>
  );
}

export default function MatrixPage() {
  const { run, isLoading, error, refetch } = useActiveRun();
  const matrix = useMatrix(run?.id);
  const cases = useCases(run?.id);
  const findings = useFindings({ run_id: run?.id, limit: 500 });
  const { toast } = useApp();
  const [actor, setActor] = useState("");
  const [tenant, setTenant] = useState("");
  const [state, setState] = useState("");
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<string | null>(null);
  const [focus, setFocus] = useState<{ r: number; c: number }>({ r: 0, c: 0 });
  const [scroll, setScroll] = useState({ top: 0, left: 0, w: 900, h: 480 });
  const box = useRef<HTMLDivElement>(null);

  const m = matrix.data;
  const rows = useMemo(() => (m?.rows ?? []).filter((r) => (!actor || r.actor === actor) && (!tenant || (r.tenant ?? "none") === tenant)), [m, actor, tenant]);
  const cols = useMemo(() => (m?.columns ?? []).filter((c) => (!q || c.key.toLowerCase().includes(q.toLowerCase())) &&
    (!state || rows.some((r) => (r.cells[c.key] ?? []).some((x) => x.state === state)))), [m, q, state, rows]);

  const caseMap = useMemo(() => new Map((cases.data ?? []).map((c) => [c.case_id, c])), [cases.data]);
  const selected = sel ? caseMap.get(sel) : undefined;
  const linked = useMemo(() => (sel ? (findings.data?.items ?? []).filter((f) => f.case_ids.includes(sel)).map((f) => f.id) : []), [sel, findings.data]);

  const c0 = Math.max(0, Math.floor(scroll.left / COL_W) - OVERSCAN);
  const c1 = Math.min(cols.length, Math.ceil((scroll.left + scroll.w) / COL_W) + OVERSCAN);
  const r0 = Math.max(0, Math.floor(scroll.top / ROW_H) - OVERSCAN);
  const r1 = Math.min(rows.length, Math.ceil((scroll.top + scroll.h) / ROW_H) + OVERSCAN);

  const onScroll = useCallback(() => {
    const el = box.current;
    if (el) setScroll({ top: el.scrollTop, left: el.scrollLeft, w: el.clientWidth, h: el.clientHeight });
  }, []);

  const move = (dr: number, dc: number) => {
    const r = Math.min(Math.max(0, focus.r + dr), Math.max(0, rows.length - 1));
    const c = Math.min(Math.max(0, focus.c + dc), Math.max(0, cols.length - 1));
    setFocus({ r, c });
    const el = box.current;
    if (el) {
      if (c * COL_W < el.scrollLeft) el.scrollLeft = c * COL_W;
      else if ((c + 1) * COL_W + 150 > el.scrollLeft + el.clientWidth) el.scrollLeft = (c + 1) * COL_W + 150 - el.clientWidth;
      if (r * ROW_H < el.scrollTop) el.scrollTop = r * ROW_H;
      else if ((r + 1) * ROW_H + ROW_H > el.scrollTop + el.clientHeight) el.scrollTop = (r + 2) * ROW_H - el.clientHeight;
    }
    requestAnimationFrame(() => document.getElementById(`mc-${r}-${c}`)?.focus());
  };
  const onKey = (e: KeyboardEvent) => {
    const k = e.key;
    if (k === "ArrowRight") { e.preventDefault(); move(0, 1); }
    else if (k === "ArrowLeft") { e.preventDefault(); move(0, -1); }
    else if (k === "ArrowDown") { e.preventDefault(); move(1, 0); }
    else if (k === "ArrowUp") { e.preventDefault(); move(-1, 0); }
    else if (k === "Home") { e.preventDefault(); move(0, -focus.c); }
    else if (k === "End") { e.preventDefault(); move(0, cols.length); }
  };

  if (isLoading || matrix.isLoading) return <Skeleton className="h-96" />;
  if (error || matrix.error) return <ErrorState error={error ?? matrix.error} onRetry={() => { void refetch(); void matrix.refetch(); }} />;
  if (!run || !m) return <EmptyState title="No matrix yet">Run a verification from the Overview or Test Studio. The matrix is built only from cases that actually executed.</EmptyState>;
  if (m.rows.length === 0) return <EmptyState title="This run executed no cases">It was a catalog-only scan. Run a behavioral verification to populate the matrix.</EmptyState>;

  const tenants = Array.from(new Set(m.rows.map((r) => r.tenant ?? "none")));
  const totalCells = Object.values(m.totals).reduce((a, b) => a + b, 0);

  return (
    <div className="grid gap-4">
      <PageHeader kicker="Executable authorization matrix" title="Authorization matrix"
        subtitle={<>Rows are identities, columns are operations on resources. Every cell comes from an executed test (<b>{totalCells}</b> of <b>{m.denominator}</b> expected assertions). Select a cell for evidence.</>}
        actions={<Button size="sm" onClick={() => void download(`/reports/${run.id}?format=csv`, `matrix-${run.id}.csv`).catch((e: Error) => toast("coral", e.message))}><Download size={14} aria-hidden /> Export CSV</Button>} />
      <Card padded>
        <div className="flex flex-wrap gap-3 items-end mb-3">
          <label className="grid gap-1 text-xs text-muted">Identity
            <Select aria-label="Filter by identity" value={actor} onChange={(e) => setActor(e.target.value)} className="w-40"><option value="">All identities</option>{m.rows.map((r) => <option key={r.actor}>{r.actor}</option>)}</Select></label>
          <label className="grid gap-1 text-xs text-muted">Tenant
            <Select aria-label="Filter by tenant" value={tenant} onChange={(e) => setTenant(e.target.value)} className="w-36"><option value="">All tenants</option>{tenants.map((t) => <option key={t}>{t}</option>)}</Select></label>
          <label className="grid gap-1 text-xs text-muted">State
            <Select aria-label="Filter by state" value={state} onChange={(e) => setState(e.target.value)} className="w-44"><option value="">Any state</option>
              {Object.keys(m.totals).map((s) => <option key={s} value={s}>{STATE_UI[s]?.text ?? s}</option>)}</Select></label>
          <label className="grid gap-1 text-xs text-muted grow max-w-xs">Column search
            <Input aria-label="Search columns" placeholder="e.g. SELECT alpha_invoice" value={q} onChange={(e) => setQ(e.target.value)} /></label>
          <div className="ml-auto"><Legend totals={m.totals} /></div>
        </div>
        <div className="grid 2xl:grid-cols-[1fr_440px] gap-4 items-start">
          <div ref={box} onScroll={onScroll} className="overflow-auto scroll-thin card-flat max-h-[62vh]" data-testid="matrix-scroll" onKeyDown={onKey}>
            <table role="grid" aria-label="Authorization matrix" aria-rowcount={rows.length + 1} aria-colcount={cols.length + 1} className="border-collapse text-xs" data-testid="matrix">
              <thead>
                <tr role="row">
                  <th scope="col" className="sticky left-0 top-0 z-30 bg-raised border-b border-r border-line text-left px-3 w-40 min-w-40" style={{ height: 64 }}>Identity ↓ / Operation →</th>
                  {c0 > 0 && <th aria-hidden style={{ width: c0 * COL_W, minWidth: c0 * COL_W }} className="sticky top-0 z-20 bg-raised border-b border-line" />}
                  {cols.slice(c0, c1).map((c) => (
                    <th key={c.key} scope="col" style={{ width: COL_W, minWidth: COL_W, maxWidth: COL_W }} className="sticky top-0 z-20 bg-raised border-b border-r border-line px-2 text-left align-bottom pb-1">
                      <div className="mono font-bold truncate" title={c.key}>{c.operation}</div>
                      <div className="mono text-muted truncate" title={c.via ?? c.resource ?? c.table ?? ""}>{c.via ?? c.resource ?? c.table}</div>
                      {c.tenant && <div className="text-muted truncate">tenant {c.tenant}</div>}
                    </th>
                  ))}
                  {c1 < cols.length && <th aria-hidden style={{ width: (cols.length - c1) * COL_W }} className="sticky top-0 z-20 bg-raised border-b border-line" />}
                </tr>
              </thead>
              <tbody>
                {r0 > 0 && <tr aria-hidden style={{ height: r0 * ROW_H }}><td /></tr>}
                {rows.slice(r0, r1).map((row, ri) => {
                  const rIdx = r0 + ri;
                  return (
                    <tr role="row" key={row.actor} style={{ height: ROW_H }}>
                      <th scope="row" className="sticky left-0 z-10 bg-raised border-b border-r border-line text-left px-3">
                        <div className="font-bold truncate">{row.actor}</div>
                        <div className="mono text-muted truncate">{row.db_role}{row.tenant ? ` · ${row.tenant}` : ""}</div>
                      </th>
                      {c0 > 0 && <td aria-hidden style={{ width: c0 * COL_W }} />}
                      {cols.slice(c0, c1).map((c, ci) => {
                        const cIdx = c0 + ci;
                        const cells: MatrixCell[] = row.cells[c.key] ?? [];
                        const cell = cells[0];
                        const ui = cell ? STATE_UI[cell.state] : undefined;
                        const isSel = !!cell && sel === cell.case_id;
                        return (
                          <td key={c.key} role="gridcell" aria-rowindex={rIdx + 2} aria-colindex={cIdx + 2} style={{ width: COL_W, minWidth: COL_W, maxWidth: COL_W }}
                            className="border-b border-r border-line p-0">
                            {cell && ui ? (
                              <button
                                id={`mc-${rIdx}-${cIdx}`} type="button" tabIndex={focus.r === rIdx && focus.c === cIdx ? 0 : -1} data-selected={isSel}
                                data-state={cell.state} data-case={cell.case_id}
                                className={clsx("matrix-cell t-fast w-full h-full px-2 flex flex-col justify-center items-start gap-0.5 hover:bg-hover", ui.cls, cell.state === "FAIL" && "bg-[color-mix(in_srgb,var(--coral)_10%,transparent)]")}
                                onFocus={() => setFocus({ r: rIdx, c: cIdx })}
                                onClick={() => { setSel(cell.case_id); setFocus({ r: rIdx, c: cIdx }); }}
                                aria-label={`${row.actor} ${c.operation} ${c.resource ?? c.table}: expected ${cell.expected}, ${cell.state === "UNKNOWN" ? "unknown" : `status ${cell.status}`}, observed ${cell.observed ?? "none"}`}
                              >
                                <span className="inline-flex items-center gap-1 font-semibold">{ui.glyph}{ui.text}{cells.length > 1 ? ` +${cells.length - 1}` : ""}</span>
                                <span className="mono text-[10px] text-muted truncate max-w-full">{cell.observed ?? ""}{cell.gate && cell.gate !== "UNKNOWN" && cell.gate !== "NONE" ? ` · ${cell.gate}` : ""}</span>
                              </button>
                            ) : <span className="text-muted px-2" aria-label="no case">·</span>}
                          </td>
                        );
                      })}
                      {c1 < cols.length && <td aria-hidden />}
                    </tr>
                  );
                })}
                {r1 < rows.length && <tr aria-hidden style={{ height: (rows.length - r1) * ROW_H }}><td /></tr>}
              </tbody>
            </table>
            {rows.length === 0 || cols.length === 0 ? <p className="p-4 text-muted text-[13px]">No cells match the current filters.</p> : null}
          </div>
          <aside aria-label="Cell evidence" className="card-flat p-4 min-h-40 2xl:sticky 2xl:top-2">
            {selected ? <CaseDetail c={selected} findingIds={linked} /> : (
              <p className="text-[13px] text-muted">Select a matrix cell (click, or arrow keys then Enter) to see the executed SQL, the deciding gate, SQLSTATE, applicable policies and baseline.</p>
            )}
          </aside>
        </div>
        <p className="text-xs text-muted mt-3">Virtualized grid: {rows.length} rows × {cols.length} columns, rendering {Math.max(0, r1 - r0)} × {Math.max(0, c1 - c0)}. Color is never the only signal: each state has a glyph and a label.</p>
      </Card>
    </div>
  );
}
