export function timeAgo(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.round(h / 24)} d ago`;
}

export const fmtDate = (iso: string | null | undefined): string => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—");

export function shortHash(h: string | null | undefined, n = 10): string {
  if (!h) return "—";
  const body = h.replace(/^sha256:/, "");
  return body.slice(0, n);
}

export const plural = (n: number, one: string, many = `${one}s`): string => `${n} ${n === 1 ? one : many}`;

export function groupBy<T>(items: T[], key: (t: T) => string): Record<string, T[]> {
  const out: Record<string, T[]> = {};
  for (const it of items) (out[key(it)] ??= []).push(it);
  return out;
}

export const SEVERITY_ORDER: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4, "Needs triage": 5 };
export const CLASS_ORDER: Record<string, number> = { CONFIRMED_VIOLATION: 0, CONFIGURATION_RISK: 1, INCONCLUSIVE: 2, UNSUPPORTED: 3 };

export function envLabel(mode: string | undefined): string {
  return mode ?? "—";
}
