import type { Envelope, Problem } from "./types";

const TOKEN_KEY = "sentinel.token";
export const getToken = (): string => sessionStorage.getItem(TOKEN_KEY) ?? "";
export const setToken = (t: string): void => {
  if (t) sessionStorage.setItem(TOKEN_KEY, t);
  else sessionStorage.removeItem(TOKEN_KEY);
};

export class ApiError extends Error {
  status: number;
  code: string;
  issues: NonNullable<Problem["issues"]>;
  constructor(p: Problem) {
    super(p.detail || p.title);
    this.status = p.status;
    this.code = p.code;
    this.issues = p.issues ?? [];
  }
}

type Listener = () => void;
const authListeners = new Set<Listener>();
export const onUnauthorized = (fn: Listener): (() => void) => {
  authListeners.add(fn);
  return () => {
    authListeners.delete(fn);
  };
};

function headers(extra?: HeadersInit): Headers {
  const h = new Headers(extra);
  h.set("X-Sentinel-Client", "web-ui");
  const t = getToken();
  if (t) h.set("Authorization", `Bearer ${t}`);
  return h;
}

async function parse(res: Response): Promise<unknown> {
  const ct = res.headers.get("content-type") ?? "";
  if (ct.includes("json")) return res.json();
  return res.text();
}

export async function api<T>(path: string, init: { method?: string; body?: unknown; signal?: AbortSignal } = {}): Promise<Envelope<T>> {
  const h = headers(init.body !== undefined ? { "Content-Type": "application/json" } : undefined);
  let res: Response;
  try {
    res = await fetch(`/api/v1${path}`, {
      method: init.method ?? "GET",
      headers: h,
      body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
      signal: init.signal,
    });
  } catch (e) {
    if ((e as Error).name === "AbortError") throw e;
    throw new ApiError({ title: "Network error", status: 0, detail: "Cannot reach the RLS Sentinel API. Is the server running?", code: "network" });
  }
  if (res.status === 204) return { data: undefined as T, meta: {} };
  const body = await parse(res);
  if (!res.ok) {
    if (res.status === 401) authListeners.forEach((f) => f());
    const p = (typeof body === "object" && body ? body : { title: "Error", status: res.status, detail: String(body), code: "error" }) as Problem;
    throw new ApiError(p);
  }
  return body as Envelope<T>;
}

export async function download(path: string, filename: string): Promise<void> {
  const res = await fetch(`/api/v1${path}`, { headers: headers() });
  if (!res.ok) {
    if (res.status === 401) authListeners.forEach((f) => f());
    const p = (await res.json().catch(() => ({ title: "Download failed", status: res.status, detail: "Download failed", code: "error" }))) as Problem;
    throw new ApiError(p);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function saveTextFile(filename: string, text: string, mime = "text/plain"): void {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export interface SseEvent { id: number; type: string; data: Record<string, unknown> }

const TERMINAL = new Set(["completed", "failed", "cancelled"]);

/** Fetch-based SSE reader (EventSource cannot send the Authorization header). Resumes with Last-Event-ID after a drop. */
export async function streamEvents(path: string, onEvent: (e: SseEvent) => void, signal: AbortSignal): Promise<void> {
  let last = 0;
  let attempts = 0;
  while (!signal.aborted) {
    try {
      const res = await fetch(`/api/v1${path}?after=${last}`, { headers: headers({ "Last-Event-ID": String(last) }), signal });
      if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
      attempts = 0;
      const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
      let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += value;
        let idx = buf.indexOf("\n\n");
        while (idx >= 0) {
          const block = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          idx = buf.indexOf("\n\n");
          let id = 0;
          let type = "message";
          let data = "";
          for (const line of block.split("\n")) {
            if (line.startsWith("id:")) id = Number(line.slice(3).trim());
            else if (line.startsWith("event:")) type = line.slice(6).trim();
            else if (line.startsWith("data:")) data += line.slice(5).trim();
          }
          if (!data) continue;
          if (id > last) last = id;
          let parsed: Record<string, unknown> = {};
          try {
            parsed = JSON.parse(data) as Record<string, unknown>;
          } catch {
            /* ignore malformed event */
          }
          onEvent({ id, type, data: parsed });
          if (TERMINAL.has(type)) return;
        }
      }
    } catch (e) {
      if (signal.aborted) return;
      if (++attempts > 6) throw e;
      await new Promise((r) => setTimeout(r, Math.min(4000, 400 * 2 ** attempts)));
    }
  }
}
