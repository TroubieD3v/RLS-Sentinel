import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

export type ThemePref = "system" | "dark" | "light";
export interface Toast { id: number; tone: "teal" | "coral" | "amber" | "blue"; text: string }

interface AppState {
  theme: ThemePref; setTheme: (t: ThemePref) => void; resolvedTheme: "dark" | "light";
  reducedMotion: boolean; setReducedMotion: (v: boolean) => void;
  activeRunId: string | null; setActiveRunId: (id: string | null) => void;
  toasts: Toast[]; toast: (tone: Toast["tone"], text: string) => void; dismissToast: (id: number) => void;
  paletteOpen: boolean; setPaletteOpen: (o: boolean) => void;
  navOpen: boolean; setNavOpen: (o: boolean) => void;
}

const Ctx = createContext<AppState | null>(null);
export function useApp(): AppState {
  const c = useContext(Ctx);
  if (!c) throw new Error("AppProvider missing");
  return c;
}

const systemDark = (): boolean => window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? true;

export function AppProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<ThemePref>(() => (localStorage.getItem("sentinel.theme") as ThemePref | null) ?? "system");
  const [osDark, setOsDark] = useState(systemDark);
  const [reducedMotion, setRm] = useState<boolean>(() => {
    const v = localStorage.getItem("sentinel.reducedMotion");
    return v === null ? (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false) : v === "1";
  });
  const [activeRunId, setActive] = useState<string | null>(() => localStorage.getItem("sentinel.activeRun"));
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [navOpen, setNavOpen] = useState(false);

  const resolvedTheme: "dark" | "light" = theme === "system" ? (osDark ? "dark" : "light") : theme;

  useEffect(() => {
    const mq = window.matchMedia?.("(prefers-color-scheme: dark)");
    if (!mq) return;
    const fn = () => setOsDark(mq.matches);
    mq.addEventListener("change", fn);
    return () => mq.removeEventListener("change", fn);
  }, []);
  useEffect(() => { document.documentElement.setAttribute("data-theme", resolvedTheme); }, [resolvedTheme]);
  useEffect(() => {
    if (reducedMotion) document.documentElement.setAttribute("data-reduced-motion", "1");
    else document.documentElement.removeAttribute("data-reduced-motion");
  }, [reducedMotion]);

  const setTheme = useCallback((t: ThemePref) => { localStorage.setItem("sentinel.theme", t); setThemeState(t); }, []);
  const setReducedMotion = useCallback((v: boolean) => { localStorage.setItem("sentinel.reducedMotion", v ? "1" : "0"); setRm(v); }, []);
  const setActiveRunId = useCallback((id: string | null) => {
    if (id) localStorage.setItem("sentinel.activeRun", id); else localStorage.removeItem("sentinel.activeRun");
    setActive(id);
  }, []);
  const dismissToast = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const toast = useCallback((tone: Toast["tone"], text: string) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t.slice(-3), { id, tone, text }]);
    setTimeout(() => dismissToast(id), 6000);
  }, [dismissToast]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPaletteOpen((o) => !o); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const value = useMemo<AppState>(() => ({
    theme, setTheme, resolvedTheme, reducedMotion, setReducedMotion, activeRunId, setActiveRunId, toasts, toast, dismissToast,
    paletteOpen, setPaletteOpen, navOpen, setNavOpen,
  }), [theme, setTheme, resolvedTheme, reducedMotion, setReducedMotion, activeRunId, setActiveRunId, toasts, toast, dismissToast, paletteOpen, navOpen]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
