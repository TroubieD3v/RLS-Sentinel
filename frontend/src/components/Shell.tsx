import * as DialogPrimitive from "@radix-ui/react-dialog";
import { useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import {
  Activity, BookOpenCheck, FlaskConical, FileText, GitCompare, History, KeyRound, LayoutDashboard, Menu, Moon, Network, PanelLeftClose, PanelLeftOpen,
  Plug, Search, Settings, ShieldAlert, Sun, Table2, TestTube2, X, Workflow,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { ApiError, onUnauthorized, setToken } from "@/api/client";
import { Button, Input, Logo, ModeBadge, Field } from "@/design-system/ui";
import { timeAgo } from "@/lib/format";
import { useActiveRun, useFindings, useHealth, useRunDetail, useSnapshot } from "@/lib/queries";
import { useApp } from "@/state/app";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/connections", label: "Connections", icon: Plug },
  { to: "/schema", label: "Schema", icon: Table2 },
  { to: "/policies", label: "Policies", icon: BookOpenCheck },
  { to: "/matrix", label: "Matrix", icon: GitCompare },
  { to: "/graph", label: "Access Graph", icon: Network },
  { to: "/studio", label: "Test Studio", icon: TestTube2 },
  { to: "/findings", label: "Findings", icon: ShieldAlert },
  { to: "/what-if", label: "What-if", icon: FlaskConical },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/history", label: "History", icon: History },
  { to: "/settings", label: "Settings", icon: Settings },
] as const;

function Sidebar({ collapsed, onToggle, onNavigate }: { collapsed: boolean; onToggle?: () => void; onNavigate?: () => void }) {
  return (
    <nav aria-label="Primary" className="h-full flex flex-col">
      <div className={clsx("h-16 flex items-center border-b border-line shrink-0", collapsed ? "justify-center px-0" : "px-5")}>
        {collapsed ? <Logo compact={false} size={26} /> : <Logo />}
      </div>
      <ul className="flex-1 overflow-auto scroll-thin p-2 grid gap-0.5 content-start">
        {NAV.map(({ to, label, icon: Icon, ...rest }) => (
          <li key={to}>
            <NavLink
              to={to}
              end={"end" in rest}
              onClick={onNavigate}
              aria-label={label}
              title={collapsed ? label : undefined}
              className={({ isActive }) =>
                clsx("t-fast flex items-center gap-3 rounded-lg h-9 text-[13px] font-semibold",
                  collapsed ? "justify-center px-0" : "px-3",
                  isActive ? "bg-raised text-ink shadow-[inset_2px_0_0_var(--teal)]" : "text-muted hover:text-ink hover:bg-hover")
              }
            >
              <Icon size={17} aria-hidden />
              {!collapsed && <span>{label}</span>}
            </NavLink>
          </li>
        ))}
      </ul>
      {onToggle && (
        <div className="p-2 border-t border-line hidden lg:block">
          <Button variant="ghost" size="sm" className="w-full" onClick={onToggle} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}>
            {collapsed ? <PanelLeftOpen size={16} aria-hidden /> : <><PanelLeftClose size={16} aria-hidden /> Collapse</>}
          </Button>
        </div>
      )}
      {!collapsed && <p className="px-5 pb-4 pt-1 text-[10px] tracking-[0.18em] uppercase text-muted">Permissions are not proof. Test them.</p>}
    </nav>
  );
}

function Topbar({ onMenu }: { onMenu: () => void }) {
  const { theme, setTheme, resolvedTheme, setPaletteOpen, activeRunId, setActiveRunId } = useApp();
  const health = useHealth();
  const { run, runs } = useActiveRun();
  const detail = useRunDetail(run?.id);
  const completed = runs.filter((r) => r.status === "completed" && r.kind !== "whatif_sandbox");
  const mode = run?.environment_mode ?? (health.data?.lab.available ? "DISPOSABLE LAB" : "READ-ONLY SOURCE");
  const pg = (detail.data?.version_info?.postgres as string | undefined) ?? undefined;
  return (
    <header className="h-16 shrink-0 flex items-center gap-3 px-3 sm:px-5 border-b border-line bg-surface/80 backdrop-blur sticky top-0 z-20">
      <Button variant="ghost" size="sm" className="md:hidden" onClick={onMenu} aria-label="Open navigation"><Menu size={18} aria-hidden /></Button>
      <div className="min-w-0 hidden sm:block">
        <div className="text-[11px] tracking-[0.14em] uppercase text-muted">Workspace</div>
        <div className="font-bold truncate" data-testid="workspace-name">default</div>
      </div>
      <div className="flex items-center gap-2 flex-wrap min-w-0" data-testid="topbar-status">
        <ModeBadge mode={mode} />
        {pg && <span className="mono text-muted hidden md:inline">PostgreSQL {pg}</span>}
        {run && <span className="text-xs text-muted hidden lg:inline">last run {timeAgo(run.completed_at ?? run.started_at)}</span>}
      </div>
      <div className="ml-auto flex items-center gap-2">
        {completed.length > 0 && (
          <label className="hidden lg:flex items-center gap-2 text-xs text-muted">
            <span className="sr-only">Active run</span>
            <select
              aria-label="Active run"
              className="h-8 max-w-[260px] rounded-lg bg-bg border border-line px-2 text-xs text-ink"
              value={activeRunId ?? run?.id ?? ""}
              onChange={(e) => setActiveRunId(e.target.value)}
            >
              {completed.map((r) => (
                <option key={r.id} value={r.id}>{r.fixture ?? "scan"}{r.variant ? ` · ${r.variant}` : ""} · {timeAgo(r.started_at)}</option>
              ))}
            </select>
          </label>
        )}
        <Button variant="secondary" size="sm" onClick={() => setPaletteOpen(true)} aria-label="Open command palette (Ctrl+K)" data-testid="palette-open">
          <Search size={14} aria-hidden /> <span className="hidden sm:inline">Search</span> <kbd className="mono hidden sm:inline text-muted border border-line rounded px-1">Ctrl K</kbd>
        </Button>
        <Button variant="ghost" size="sm" aria-label={`Switch to ${resolvedTheme === "dark" ? "light" : "dark"} theme`}
          onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")} title={`Theme: ${theme}`}>
          {resolvedTheme === "dark" ? <Sun size={16} aria-hidden /> : <Moon size={16} aria-hidden />}
        </Button>
      </div>
    </header>
  );
}

function CommandPalette() {
  const { paletteOpen, setPaletteOpen, setActiveRunId } = useApp();
  const nav = useNavigate();
  const [q, setQ] = useState("");
  const [idx, setIdx] = useState(0);
  const { run, runs } = useActiveRun();
  const snap = useSnapshot(run?.snapshot_id);
  const findings = useFindings({ run_id: run?.id, limit: 200 });
  const inputRef = useRef<HTMLInputElement>(null);

  const items = useMemo(() => {
    const out: { id: string; group: string; label: string; hint?: string; go: () => void }[] = [];
    for (const n of NAV) out.push({ id: `p:${n.to}`, group: "Go to", label: n.label, go: () => nav(n.to) });
    for (const r of runs.filter((x) => x.status === "completed").slice(0, 15))
      out.push({ id: `r:${r.id}`, group: "Runs", label: `${r.fixture ?? "scan"} ${r.variant ?? ""}`.trim(), hint: timeAgo(r.started_at), go: () => { setActiveRunId(r.id); nav("/"); } });
    for (const t of snap.data?.tables ?? []) out.push({ id: `t:${t.schema}.${t.name}`, group: "Tables", label: `${t.schema}.${t.name}`, hint: t.rls_enabled ? "RLS on" : "RLS off", go: () => nav(`/schema?table=${encodeURIComponent(`${t.schema}.${t.name}`)}`) });
    for (const r of snap.data?.roles ?? []) if (!r.system) out.push({ id: `ro:${r.name}`, group: "Roles", label: r.name, go: () => nav(`/graph?role=${encodeURIComponent(r.name)}`) });
    for (const p of snap.data?.policies ?? []) out.push({ id: `po:${p.table}:${p.name}`, group: "Policies", label: p.name, hint: p.table, go: () => nav(`/policies?table=${encodeURIComponent(p.table)}`) });
    for (const f of findings.data?.items ?? []) out.push({ id: `f:${f.id}`, group: "Findings", label: `${f.rule_id} · ${f.subject}`, hint: f.severity, go: () => nav(`/findings?id=${f.id}`) });
    return out;
  }, [nav, runs, snap.data, findings.data, setActiveRunId]);

  const shown = useMemo(() => {
    const s = q.trim().toLowerCase();
    return (s ? items.filter((i) => `${i.label} ${i.hint ?? ""} ${i.group}`.toLowerCase().includes(s)) : items.slice(0, 14)).slice(0, 40);
  }, [items, q]);

  useEffect(() => { setIdx(0); }, [q, paletteOpen]);
  useEffect(() => { if (paletteOpen) { setQ(""); setTimeout(() => inputRef.current?.focus(), 30); } }, [paletteOpen]);

  const run_ = (i: number) => { const it = shown[i]; if (it) { setPaletteOpen(false); it.go(); } };
  return (
    <DialogPrimitive.Root open={paletteOpen} onOpenChange={setPaletteOpen}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/60" />
        <DialogPrimitive.Content className="card enter fixed z-50 left-1/2 top-[12vh] -translate-x-1/2 w-[min(94vw,640px)] overflow-hidden" aria-describedby={undefined}>
          <DialogPrimitive.Title className="sr-only">Command palette</DialogPrimitive.Title>
          <div className="flex items-center gap-2 px-3 border-b border-line">
            <Search size={16} className="text-muted" aria-hidden />
            <input
              ref={inputRef} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Jump to scans, tables, roles, policies, findings…"
              aria-label="Search" role="combobox" aria-expanded="true" aria-controls="palette-list" aria-activedescendant={shown[idx] ? `pal-${idx}` : undefined}
              className="flex-1 h-12 bg-transparent outline-none text-[14px]"
              onKeyDown={(e) => {
                if (e.key === "ArrowDown") { e.preventDefault(); setIdx((i) => Math.min(shown.length - 1, i + 1)); }
                else if (e.key === "ArrowUp") { e.preventDefault(); setIdx((i) => Math.max(0, i - 1)); }
                else if (e.key === "Enter") { e.preventDefault(); run_(idx); }
              }}
            />
            <kbd className="mono text-muted border border-line rounded px-1 text-xs">Esc</kbd>
          </div>
          <ul id="palette-list" role="listbox" className="max-h-[50vh] overflow-auto scroll-thin p-1">
            {shown.length === 0 && <li className="px-3 py-6 text-center text-muted text-[13px]">No matches in the active run.</li>}
            {shown.map((it, i) => (
              <li key={it.id} id={`pal-${i}`} role="option" aria-selected={i === idx}
                onMouseMove={() => setIdx(i)} onClick={() => run_(i)}
                className={clsx("t-fast flex items-center gap-3 px-3 h-9 rounded-md cursor-pointer text-[13px]", i === idx && "bg-hover")}>
                <span className="text-[10px] w-16 shrink-0 uppercase tracking-widest text-muted">{it.group}</span>
                <span className="truncate font-medium">{it.label}</span>
                {it.hint && <span className="ml-auto text-xs text-muted truncate">{it.hint}</span>}
              </li>
            ))}
          </ul>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}

function UnlockDialog() {
  const [open, setOpen] = useState(false);
  const [val, setVal] = useState("");
  const qc = useQueryClient();
  useEffect(() => onUnauthorized(() => setOpen(true)), []);
  return (
    <DialogPrimitive.Root open={open} onOpenChange={setOpen}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-[70] bg-black/70" />
        <DialogPrimitive.Content className="card enter fixed z-[80] left-1/2 top-[18vh] -translate-x-1/2 w-[min(94vw,460px)] p-5" aria-describedby="unlock-d">
          <DialogPrimitive.Title className="font-bold text-base flex items-center gap-2"><KeyRound size={16} aria-hidden /> API token required</DialogPrimitive.Title>
          <p id="unlock-d" className="text-xs text-muted mt-1 mb-3">This server runs in token mode. The token is kept in this tab&apos;s sessionStorage only and is sent as a Bearer header.</p>
          <form onSubmit={(e) => { e.preventDefault(); setToken(val.trim()); setOpen(false); setVal(""); void qc.invalidateQueries(); }} className="grid gap-3">
            <Field label="Token" htmlFor="tok"><Input id="tok" type="password" autoComplete="off" value={val} onChange={(e) => setVal(e.target.value)} /></Field>
            <Button variant="primary" type="submit" disabled={!val.trim()}>Unlock</Button>
          </form>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}

function Toasts() {
  const { toasts, dismissToast } = useApp();
  return (
    <div className="fixed z-[90] right-4 bottom-4 grid gap-2 w-[min(92vw,380px)]" aria-live="polite" aria-atomic="false">
      {toasts.map((t) => (
        <div key={t.id} className={clsx("card enter px-3.5 py-2.5 flex items-start gap-2 text-[13px]")} role="status" style={{ borderLeft: `3px solid var(--${t.tone === "blue" ? "blue" : t.tone})` }}>
          <Activity size={14} className="mt-0.5 shrink-0" aria-hidden />
          <span className="flex-1">{t.text}</span>
          <button className="text-muted hover:text-ink" aria-label="Dismiss notification" onClick={() => dismissToast(t.id)}><X size={14} aria-hidden /></button>
        </div>
      ))}
    </div>
  );
}

export function Shell() {
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem("sentinel.nav") === "collapsed");
  const { navOpen, setNavOpen } = useApp();
  const loc = useLocation();
  useEffect(() => { setNavOpen(false); }, [loc.pathname, setNavOpen]);
  const toggle = () => setCollapsed((c) => { localStorage.setItem("sentinel.nav", c ? "expanded" : "collapsed"); return !c; });
  return (
    <div className="h-full flex">
      <a href="#main" className="sr-only-focusable fixed top-2 left-2 z-[100] card px-3 py-2 font-semibold">Skip to content</a>
      <aside className={clsx("hidden md:block shrink-0 border-r border-line bg-surface t-fast", collapsed ? "w-16" : "w-16 lg:w-64")}>
        <div className="hidden lg:block h-full"><Sidebar collapsed={collapsed} onToggle={toggle} /></div>
        <div className="lg:hidden h-full"><Sidebar collapsed /></div>
      </aside>
      <DialogPrimitive.Root open={navOpen} onOpenChange={setNavOpen}>
        <DialogPrimitive.Portal>
          <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/60 md:hidden" />
          <DialogPrimitive.Content className="fixed z-50 inset-y-0 left-0 w-72 bg-surface border-r border-line md:hidden enter" aria-describedby={undefined}>
            <DialogPrimitive.Title className="sr-only">Navigation</DialogPrimitive.Title>
            <Sidebar collapsed={false} onNavigate={() => setNavOpen(false)} />
          </DialogPrimitive.Content>
        </DialogPrimitive.Portal>
      </DialogPrimitive.Root>
      <div className="flex-1 min-w-0 flex flex-col">
        <Topbar onMenu={() => setNavOpen(true)} />
        <main id="main" tabIndex={-1} className="flex-1 overflow-auto scroll-thin outline-none">
          <div className="mx-auto max-w-[1600px] px-3 sm:px-5 py-5"><Outlet /></div>
        </main>
      </div>
      <CommandPalette />
      <UnlockDialog />
      <Toasts />
    </div>
  );
}

export function PageHeader({ title, subtitle, actions, kicker }: { title: string; subtitle?: ReactNode; actions?: ReactNode; kicker?: string }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3 mb-5">
      <div className="min-w-0">
        {kicker && <div className="text-[11px] tracking-[0.18em] uppercase text-muted flex items-center gap-1.5"><Workflow size={12} aria-hidden /> {kicker}</div>}
        <h1 className="text-[22px] font-bold leading-tight">{title}</h1>
        {subtitle && <p className="text-[13px] text-muted mt-1 max-w-3xl">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2 flex-wrap">{actions}</div>}
    </div>
  );
}

export function describeError(e: unknown): string {
  return e instanceof ApiError || e instanceof Error ? e.message : "Unexpected error";
}
