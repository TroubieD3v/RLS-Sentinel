import * as DialogPrimitive from "@radix-ui/react-dialog";
import { useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import {
  Activity, BookOpenCheck, ChevronDown, ChevronRight, Database, Eye, FlaskConical, FileText, GitCompare, History, KeyRound, LayoutDashboard, Layers, Menu, Moon,
  Network, PanelLeftClose, PanelLeftOpen, Plug, Search, Settings, ShieldAlert, Sun, Table2, TestTube2, X,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { ApiError, onUnauthorized, setToken } from "@/api/client";
import { Button, Input, Logo, ModeBadge, Field } from "@/design-system/ui";
import { timeAgo } from "@/lib/format";
import { useActiveRun, useFindings, useHealth, useRunDetail, useSnapshot } from "@/lib/queries";
import { useApp } from "@/state/app";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true, group: "Workspace" },
  { to: "/connections", label: "Connections", icon: Plug, group: "Workspace" },
  { to: "/schema", label: "Schema", icon: Table2, group: "Catalog" },
  { to: "/policies", label: "Policies", icon: BookOpenCheck, group: "Catalog" },
  { to: "/graph", label: "Access Graph", icon: Network, group: "Catalog" },
  { to: "/studio", label: "Test Studio", icon: TestTube2, group: "Verification" },
  { to: "/matrix", label: "Matrix", icon: GitCompare, group: "Verification" },
  { to: "/what-if", label: "What-if", icon: FlaskConical, group: "Verification" },
  { to: "/findings", label: "Findings", icon: ShieldAlert, group: "Results" },
  { to: "/reports", label: "Reports", icon: FileText, group: "Results" },
  { to: "/history", label: "History", icon: History, group: "Results" },
  { to: "/settings", label: "Settings", icon: Settings, group: "Workspace" },
] as const;
const GROUPS = ["Workspace", "Catalog", "Verification", "Results"] as const;

/** Database navigator: the active snapshot's database → schemas → tables, linking into the schema explorer. */
function DbNavigator() {
  const { run } = useActiveRun();
  const snap = useSnapshot(run?.snapshot_id);
  const [sp] = useSearchParams();
  const loc = useLocation();
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const data = snap.data;
  const bySchema = useMemo(() => {
    const m = new Map<string, NonNullable<typeof data>["tables"]>();
    for (const t of data?.tables ?? []) m.set(t.schema, [...(m.get(t.schema) ?? []), t]);
    return m;
  }, [data]);
  const current = loc.pathname === "/schema" ? sp.get("table") : null;
  return (
    <section aria-label="Database navigator" className="border-t border-line min-h-0 flex flex-col">
      <h2 className="h-7 shrink-0 flex items-center px-3 text-[11.5px] font-medium text-muted">Database navigator</h2>
      {!data ? (
        <p className="px-3 pb-3 text-[12px] text-muted">No snapshot yet. Run a scan or verification.</p>
      ) : (
        <ul className="overflow-auto scroll-thin pb-2 text-[12.5px]">
          <li className="flex items-center gap-1.5 h-6 px-3"><Database size={13} className="text-muted shrink-0" aria-hidden /><span className="truncate">{data.database}</span>
            <span className="ml-auto mono text-[11px] text-muted">PG {data.postgres_version}</span></li>
          {[...bySchema.entries()].map(([schema, ts]) => {
            const isOpen = open[schema] ?? true;
            return (
              <li key={schema}>
                <button type="button" aria-expanded={isOpen} onClick={() => setOpen((o) => ({ ...o, [schema]: !isOpen }))}
                  className="t-fast w-full flex items-center gap-1 h-6 pl-5 pr-3 hover:bg-hover text-left">
                  {isOpen ? <ChevronDown size={12} className="text-muted" aria-hidden /> : <ChevronRight size={12} className="text-muted" aria-hidden />}
                  <Layers size={13} className="text-muted shrink-0" aria-hidden /><span className="truncate">{schema}</span><span className="ml-auto mono text-[11px] text-muted">{ts.length}</span>
                </button>
                {isOpen && (
                  <ul>
                    {ts.map((t) => {
                      const key = `${t.schema}.${t.name}`;
                      const view = t.kind === "view" || t.kind === "materialized_view";
                      const Icon = view ? Eye : Table2;
                      return (
                        <li key={key}>
                          <Link to={`/schema?table=${encodeURIComponent(key)}`} aria-current={current === key ? "page" : undefined}
                            className={clsx("t-fast flex items-center gap-1.5 h-6 pl-10 pr-3 hover:bg-hover", current === key && "bg-sel")}>
                            <Icon size={13} className={clsx("shrink-0", !view && !t.rls_enabled ? "tone-amber" : "text-muted")} aria-hidden />
                            <span className="truncate mono text-[12px]">{t.name}</span>
                            {!view && <span className={clsx("ml-auto text-[11px]", t.rls_enabled ? "text-muted" : "tone-amber")}>{t.rls_enabled ? (t.rls_forced ? "rls·force" : "rls") : "no rls"}</span>}
                          </Link>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

function Sidebar({ collapsed, onToggle, onNavigate, navigator = false }: { collapsed: boolean; onToggle?: () => void; onNavigate?: () => void; navigator?: boolean }) {
  return (
    <div className="h-full flex flex-col">
      <nav aria-label="Primary" className={clsx("shrink-0 overflow-auto scroll-thin py-1.5", navigator && "max-h-[58%]")}>
        {GROUPS.map((g) => (
          <div key={g} className="mb-1">
            {!collapsed && <div className="h-6 flex items-center px-3 text-[11.5px] font-medium text-muted">{g}</div>}
            <ul className="grid">
              {NAV.filter((n) => n.group === g).map(({ to, label, icon: Icon, ...rest }) => (
                <li key={to}>
                  <NavLink
                    to={to}
                    end={"end" in rest}
                    onClick={onNavigate}
                    aria-label={label}
                    title={collapsed ? label : undefined}
                    className={({ isActive }) =>
                      clsx("t-fast flex items-center gap-2 h-7 text-[13px] border-l-2",
                        collapsed ? "justify-center px-0" : "pl-4 pr-3",
                        isActive ? "bg-sel text-ink border-sky" : "text-muted border-transparent hover:text-ink hover:bg-hover")
                    }
                  >
                    <Icon size={15} aria-hidden className="shrink-0" />
                    {!collapsed && <span className="truncate">{label}</span>}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>
      {navigator && !collapsed ? <DbNavigator /> : <div className="flex-1" />}
      {onToggle && (
        <div className="p-1.5 border-t border-line hidden lg:block mt-auto">
          <Button variant="ghost" size="sm" className="w-full" onClick={onToggle} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}>
            {collapsed ? <PanelLeftOpen size={15} aria-hidden /> : <><PanelLeftClose size={15} aria-hidden /> Collapse</>}
          </Button>
        </div>
      )}
    </div>
  );
}

function Toolbar({ onMenu }: { onMenu: () => void }) {
  const { theme, setTheme, resolvedTheme, setPaletteOpen, activeRunId, setActiveRunId } = useApp();
  const health = useHealth();
  const { run, runs } = useActiveRun();
  const completed = runs.filter((r) => r.status === "completed" && r.kind !== "whatif_sandbox");
  const mode = run?.environment_mode ?? (health.data?.lab.available ? "DISPOSABLE LAB" : "READ-ONLY SOURCE");
  return (
    <header className="h-10 shrink-0 flex items-center gap-2 px-2 sm:px-3 border-b border-line bg-chrome z-20">
      <Button variant="ghost" size="sm" className="md:hidden !px-1.5" onClick={onMenu} aria-label="Open navigation"><Menu size={17} aria-hidden /></Button>
      <Logo />
      <span className="hidden sm:block h-4 w-px bg-line mx-1.5" aria-hidden />
      <div className="min-w-0 hidden sm:flex items-center gap-1.5 text-[12.5px]">
        <span className="text-muted">Workspace</span>
        <span className="font-medium truncate" data-testid="workspace-name">default</span>
      </div>
      <div className="flex items-center gap-2 min-w-0" data-testid="topbar-status">
        <ModeBadge mode={mode} />
      </div>
      <div className="ml-auto flex items-center gap-1.5">
        {completed.length > 0 && (
          <label className="hidden lg:flex items-center gap-1.5 text-[12px] text-muted">
            <span>Run</span>
            <select
              aria-label="Active run"
              className="h-7 max-w-[280px] rounded-[3px] bg-low border border-line px-1.5 text-[12px] text-ink"
              value={activeRunId ?? run?.id ?? ""}
              onChange={(e) => setActiveRunId(e.target.value)}
            >
              {completed.map((r) => (
                <option key={r.id} value={r.id}>{r.fixture ?? "scan"}{r.variant ? ` · ${r.variant}` : ""} · {timeAgo(r.started_at)}</option>
              ))}
            </select>
          </label>
        )}
        <Button variant="secondary" size="sm" onClick={() => setPaletteOpen(true)} aria-label="Open command palette (Ctrl+K)" data-testid="palette-open" className="sm:min-w-[200px] !justify-start">
          <Search size={13} aria-hidden className="text-muted" /> <span className="hidden sm:inline text-muted font-normal">Search objects…</span> <kbd className="mono hidden sm:inline ml-auto text-[11px] text-muted">Ctrl K</kbd>
        </Button>
        <Button variant="ghost" size="sm" className="!px-1.5" aria-label={`Switch to ${resolvedTheme === "dark" ? "light" : "dark"} theme`}
          onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")} title={`Theme: ${theme}`}>
          {resolvedTheme === "dark" ? <Sun size={15} aria-hidden /> : <Moon size={15} aria-hidden />}
        </Button>
      </div>
    </header>
  );
}

/** Editor tab strip: the open page as a tab, with the run it is showing. Decorative; the page has its own h1. */
function EditorTabs() {
  const loc = useLocation();
  const { run } = useActiveRun();
  const item = NAV.find((n) => (n.to === "/" ? loc.pathname === "/" : loc.pathname.startsWith(n.to)));
  const Icon = item?.icon ?? FileText;
  return (
    <div className="h-8 shrink-0 hidden sm:flex items-end gap-px px-2 border-b border-line bg-chrome" aria-hidden="true">
      <div className="h-[30px] -mb-px flex items-center gap-1.5 px-3 bg-bg border border-line border-b-bg border-t-2 border-t-sky rounded-t-[3px] text-[12.5px]">
        <Icon size={13} className="text-muted" />
        <span>{item?.label ?? "Not found"}</span>
        {run && item && item.to !== "/settings" && item.to !== "/connections" && (
          <span className="text-muted mono text-[11.5px]">· {run.fixture ?? "scan"}{run.variant ? `:${run.variant}` : ""}</span>
        )}
      </div>
    </div>
  );
}

function StatusBar() {
  const health = useHealth();
  const { run } = useActiveRun();
  const detail = useRunDetail(run?.id);
  const findings = useFindings({ run_id: run?.id, limit: 200 });
  const pg = (detail.data?.version_info?.postgres as string | undefined) ?? undefined;
  const lab = health.data?.lab;
  const confirmed = (findings.data?.items ?? []).filter((f) => f.evidence_class === "CONFIRMED_VIOLATION").length;
  const cell = "flex items-center gap-1.5 px-2.5 border-r border-line h-full whitespace-nowrap";
  return (
    <footer className="h-6 shrink-0 hidden sm:flex items-center border-t border-line bg-chrome text-[11.5px] text-muted overflow-hidden" aria-label="Status">
      <span className={cell}><span className={clsx("inline-block w-1.5 h-1.5 rounded-[1px]", lab?.available ? "bg-teal" : "bg-amber")} aria-hidden />
        {lab?.available ? `Disposable lab · ${lab.backend ?? "ready"}` : "No disposable lab"}</span>
      {pg && <span className={cell}>PostgreSQL {pg}</span>}
      {run && <span className={cell}>Last run {timeAgo(run.completed_at ?? run.started_at)}</span>}
      {run && <span className={cell}>{confirmed} confirmed violation{confirmed === 1 ? "" : "s"}</span>}
      <span className="ml-auto px-2.5">Read-only catalog queries on source databases</span>
    </footer>
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
        <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/50" />
        <DialogPrimitive.Content className="card enter fixed z-50 left-1/2 top-[12vh] -translate-x-1/2 w-[min(94vw,620px)] overflow-hidden" aria-describedby={undefined}>
          <DialogPrimitive.Title className="sr-only">Command palette</DialogPrimitive.Title>
          <div className="flex items-center gap-2 px-3 border-b border-line bg-low">
            <Search size={14} className="text-muted" aria-hidden />
            <input
              ref={inputRef} value={q} onChange={(e) => setQ(e.target.value)} placeholder="Jump to scans, tables, roles, policies, findings…"
              aria-label="Search" role="combobox" aria-expanded="true" aria-controls="palette-list" aria-activedescendant={shown[idx] ? `pal-${idx}` : undefined}
              className="flex-1 h-10 bg-transparent outline-none text-[13px]"
              onKeyDown={(e) => {
                if (e.key === "ArrowDown") { e.preventDefault(); setIdx((i) => Math.min(shown.length - 1, i + 1)); }
                else if (e.key === "ArrowUp") { e.preventDefault(); setIdx((i) => Math.max(0, i - 1)); }
                else if (e.key === "Enter") { e.preventDefault(); run_(idx); }
              }}
            />
            <kbd className="mono text-muted text-[11px]">Esc</kbd>
          </div>
          <ul id="palette-list" role="listbox" className="max-h-[50vh] overflow-auto scroll-thin py-1">
            {shown.length === 0 && <li className="px-3 py-6 text-center text-muted text-[12.5px]">No matches in the active run.</li>}
            {shown.map((it, i) => (
              <li key={it.id} id={`pal-${i}`} role="option" aria-selected={i === idx}
                onMouseMove={() => setIdx(i)} onClick={() => run_(i)}
                className={clsx("flex items-center gap-3 px-3 h-7 cursor-pointer text-[12.5px]", i === idx && "bg-sel")}>
                <span className="text-[11.5px] w-16 shrink-0 text-muted">{it.group}</span>
                <span className="truncate">{it.label}</span>
                {it.hint && <span className="ml-auto text-[11.5px] text-muted truncate">{it.hint}</span>}
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
        <DialogPrimitive.Overlay className="fixed inset-0 z-[70] bg-black/60" />
        <DialogPrimitive.Content className="card enter fixed z-[80] left-1/2 top-[18vh] -translate-x-1/2 w-[min(94vw,440px)] p-4" aria-describedby="unlock-d">
          <DialogPrimitive.Title className="font-semibold text-[13px] flex items-center gap-2"><KeyRound size={14} aria-hidden /> API token required</DialogPrimitive.Title>
          <p id="unlock-d" className="text-[12px] text-muted mt-1 mb-3">This server runs in token mode. The token is kept in this tab&apos;s sessionStorage only and is sent as a Bearer header.</p>
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
    <div className="fixed z-[90] right-3 bottom-8 grid gap-2 w-[min(92vw,360px)]" aria-live="polite" aria-atomic="false">
      {toasts.map((t) => (
        <div key={t.id} className={clsx("card enter px-3 py-2 flex items-start gap-2 text-[12.5px]")} role="status" style={{ borderLeft: `2px solid var(--${t.tone === "blue" ? "blue" : t.tone})` }}>
          <Activity size={13} className="mt-0.5 shrink-0 text-muted" aria-hidden />
          <span className="flex-1">{t.text}</span>
          <button className="text-muted hover:text-ink" aria-label="Dismiss notification" onClick={() => dismissToast(t.id)}><X size={13} aria-hidden /></button>
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
    <div className="h-full flex flex-col">
      <a href="#main" className="sr-only-focusable fixed top-2 left-2 z-[100] card px-3 py-1.5 font-medium">Skip to content</a>
      <Toolbar onMenu={() => setNavOpen(true)} />
      <div className="flex-1 min-h-0 flex">
        <aside className={clsx("hidden md:block shrink-0 border-r border-line bg-surface t-fast", collapsed ? "w-12" : "w-12 lg:w-[260px]")}>
          <div className="hidden lg:block h-full"><Sidebar collapsed={collapsed} onToggle={toggle} navigator /></div>
          <div className="lg:hidden h-full"><Sidebar collapsed /></div>
        </aside>
        <DialogPrimitive.Root open={navOpen} onOpenChange={setNavOpen}>
          <DialogPrimitive.Portal>
            <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/50 md:hidden" />
            <DialogPrimitive.Content className="fixed z-50 inset-y-0 left-0 w-64 bg-surface border-r border-line md:hidden enter" aria-describedby={undefined}>
              <DialogPrimitive.Title className="sr-only">Navigation</DialogPrimitive.Title>
              <div className="h-10 flex items-center px-3 border-b border-line bg-chrome"><Logo /></div>
              <Sidebar collapsed={false} onNavigate={() => setNavOpen(false)} />
            </DialogPrimitive.Content>
          </DialogPrimitive.Portal>
        </DialogPrimitive.Root>
        <div className="flex-1 min-w-0 flex flex-col">
          <EditorTabs />
          <main id="main" tabIndex={-1} className="flex-1 overflow-auto scroll-thin outline-none">
            <div className="mx-auto max-w-[1600px] px-3 sm:px-4 py-4"><Outlet /></div>
          </main>
        </div>
      </div>
      <StatusBar />
      <CommandPalette />
      <UnlockDialog />
      <Toasts />
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode; kicker?: string }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 mb-1">
      <div className="min-w-0">
        <h1 className="text-[17px] font-semibold leading-tight">{title}</h1>
        {subtitle && <p className="text-[12.5px] text-muted mt-1 max-w-3xl">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2 flex-wrap">{actions}</div>}
    </div>
  );
}

export function describeError(e: unknown): string {
  return e instanceof ApiError || e instanceof Error ? e.message : "Unexpected error";
}
