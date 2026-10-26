import * as DialogPrimitive from "@radix-ui/react-dialog";
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import clsx from "clsx";
import {
  AlertTriangle, Ban, Check, CheckCircle2, CircleDashed, Copy, HelpCircle, Info, Loader2, Radio, ShieldAlert, ShieldCheck, X, XCircle,
} from "lucide-react";
import { forwardRef, useState, type ButtonHTMLAttributes, type ReactNode } from "react";

/* ───────────────────────────── brand ───────────────────────────── */
export function Logo({ size = 28, compact = false }: { size?: number; compact?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2.5 text-ink" aria-label="RLS Sentinel">
      <svg width={size} height={size} viewBox="0 0 32 32" role="img" aria-hidden="true">
        <ellipse cx="16" cy="7" rx="10" ry="4" fill="none" stroke="var(--teal)" strokeWidth="2" />
        <path d="M6 7v18c0 2.2 4.5 4 10 4s10-1.8 10-4V7" fill="none" stroke="var(--teal)" strokeWidth="2" />
        <path d="M9 17c2-3 4.2-4.4 7-4.4s5 1.4 7 4.4c-2 3-4.2 4.4-7 4.4S11 20 9 17Z" fill="none" stroke="var(--violet)" strokeWidth="1.8" />
        <circle cx="16" cy="17" r="2.3" fill="var(--violet)" />
      </svg>
      <span className="font-bold tracking-[0.16em] text-[13px] whitespace-nowrap">
        {compact ? "RLS Sentinel" : <>RLS <span className="text-muted">/</span> SENTINEL</>}
      </span>
    </span>
  );
}

/* ───────────────────────────── lozenges ───────────────────────────── */
type Tone = "teal" | "coral" | "amber" | "violet" | "blue" | "muted";
const TONE_CLASS: Record<Tone, string> = { teal: "tone-teal", coral: "tone-coral", amber: "tone-amber", violet: "tone-violet", blue: "tone-blue", muted: "tone-muted" };

export function Lozenge({ tone, icon, children, title }: { tone: Tone; icon?: ReactNode; children: ReactNode; title?: string }) {
  return (
    <span className={clsx("lozenge", TONE_CLASS[tone])} title={title}>
      {icon}
      {children}
    </span>
  );
}

const ic = { size: 12, "aria-hidden": true } as const;

/** Provenance lozenges required by the design spec: CATALOG FACT / STATIC RISK / RUNTIME VERIFIED / INSUFFICIENT DATA. */
export function ProvenanceLozenge({ kind }: { kind: "catalog" | "static" | "runtime" | "insufficient" }) {
  switch (kind) {
    case "catalog": return <Lozenge tone="blue" icon={<Info {...ic} />}>Catalog fact</Lozenge>;
    case "static": return <Lozenge tone="amber" icon={<AlertTriangle {...ic} />}>Static risk</Lozenge>;
    case "runtime": return <Lozenge tone="teal" icon={<ShieldCheck {...ic} />}>Runtime verified</Lozenge>;
    default: return <Lozenge tone="muted" icon={<HelpCircle {...ic} />}>Insufficient data</Lozenge>;
  }
}

export function EvidenceLozenge({ cls }: { cls: string }) {
  switch (cls) {
    case "CONFIRMED_VIOLATION": return <Lozenge tone="coral" icon={<ShieldAlert {...ic} />}>Confirmed violation</Lozenge>;
    case "CONFIGURATION_RISK": return <Lozenge tone="amber" icon={<AlertTriangle {...ic} />}>Configuration risk</Lozenge>;
    case "INCONCLUSIVE": return <Lozenge tone="blue" icon={<HelpCircle {...ic} />}>Inconclusive</Lozenge>;
    case "EXPECTED_DENIAL": return <Lozenge tone="violet" icon={<Ban {...ic} />}>Expected denial</Lozenge>;
    case "VERIFIED_ALLOW": return <Lozenge tone="teal" icon={<CheckCircle2 {...ic} />}>Verified allow</Lozenge>;
    default: return <Lozenge tone="muted" icon={<CircleDashed {...ic} />}>Unsupported</Lozenge>;
  }
}

export function StatusLozenge({ status }: { status: string }) {
  switch (status) {
    case "PASS": return <Lozenge tone="teal" icon={<Check {...ic} />}>Pass</Lozenge>;
    case "FAIL": return <Lozenge tone="coral" icon={<XCircle {...ic} />}>Fail</Lozenge>;
    case "INCONCLUSIVE": return <Lozenge tone="amber" icon={<HelpCircle {...ic} />}>Inconclusive</Lozenge>;
    case "ERROR": return <Lozenge tone="coral" icon={<AlertTriangle {...ic} />}>Error</Lozenge>;
    case "running": return <Lozenge tone="blue" icon={<Loader2 {...ic} className="animate-spin" />}>Running</Lozenge>;
    case "queued": return <Lozenge tone="muted" icon={<Radio {...ic} />}>Queued</Lozenge>;
    case "completed": return <Lozenge tone="teal" icon={<Check {...ic} />}>Completed</Lozenge>;
    case "failed": return <Lozenge tone="coral" icon={<XCircle {...ic} />}>Failed</Lozenge>;
    case "cancelled": return <Lozenge tone="muted" icon={<Ban {...ic} />}>Cancelled</Lozenge>;
    default: return <Lozenge tone="muted">{status}</Lozenge>;
  }
}

export function SeverityLozenge({ severity }: { severity: string }) {
  const tone: Tone = severity === "Critical" || severity === "High" ? "coral" : severity === "Medium" ? "amber" : severity === "Low" ? "blue" : severity === "Needs triage" ? "violet" : "muted";
  return <Lozenge tone={tone}>{severity}</Lozenge>;
}

export function ModeBadge({ mode }: { mode: string }) {
  const lab = mode.includes("LAB") || mode.includes("SANDBOX");
  return (
    <Lozenge tone={lab ? "violet" : "teal"} icon={lab ? <ShieldAlert {...ic} /> : <ShieldCheck {...ic} />} title={lab ? "Mutating tests run only in a disposable database" : "Bounded pg_catalog queries only; no DDL, DML or row data"}>
      {mode}
    </Lozenge>
  );
}

export const DemoTag = () => <Lozenge tone="amber" title="Synthetic bundled fixture data">DEMO</Lozenge>;

/* ───────────────────────────── controls ───────────────────────────── */
type BtnProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" | "danger"; size?: "sm" | "md"; loading?: boolean };
export const Button = forwardRef<HTMLButtonElement, BtnProps>(function Button({ variant = "secondary", size = "md", loading, className, children, disabled, ...rest }, ref) {
  return (
    <button
      ref={ref}
      disabled={disabled || loading}
      className={clsx(
        "t-fast inline-flex items-center justify-center gap-2 rounded-lg font-semibold border select-none disabled:opacity-50 disabled:cursor-not-allowed",
        size === "sm" ? "h-8 px-3 text-xs" : "h-9 px-4 text-[13px]",
        variant === "primary" && "bg-teal text-[var(--on-accent)] border-transparent hover:brightness-110",
        variant === "secondary" && "bg-raised text-ink border-line hover:bg-hover",
        variant === "ghost" && "bg-transparent text-muted border-transparent hover:bg-hover hover:text-ink",
        variant === "danger" && "bg-transparent text-coral border-coral hover:bg-hover",
        className,
      )}
      {...rest}
    >
      {loading && <Loader2 size={14} className="animate-spin" aria-hidden />}
      {children}
    </button>
  );
});

export function Field({ label, hint, children, htmlFor }: { label: string; hint?: ReactNode; children: ReactNode; htmlFor?: string }) {
  return (
    <div className="grid gap-1.5">
      <label htmlFor={htmlFor} className="text-xs font-semibold text-muted tracking-wide uppercase">{label}</label>
      {children}
      {hint && <p className="text-xs text-muted">{hint}</p>}
    </div>
  );
}

export const inputCls = "w-full rounded-lg bg-bg border border-line px-3 h-9 text-[13px] text-ink placeholder:text-muted t-fast focus:border-sky";
export const Input = forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(function Input({ className, ...p }, ref) {
  return <input ref={ref} className={clsx(inputCls, className)} {...p} />;
});
export const Select = forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(function Select({ className, ...p }, ref) {
  return <select ref={ref} className={clsx(inputCls, "pr-8", className)} {...p} />;
});

/* ───────────────────────────── surfaces ───────────────────────────── */
export function Card({ title, subtitle, actions, children, className, padded = true, id }: {
  title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; padded?: boolean; id?: string;
}) {
  return (
    <section id={id} className={clsx("card", className)} aria-labelledby={id ? `${id}-t` : undefined}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-3 px-4 pt-3.5 pb-2.5">
          <div className="min-w-0">
            {title && <h2 id={id ? `${id}-t` : undefined} className="text-[13px] font-bold tracking-wide uppercase text-ink">{title}</h2>}
            {subtitle && <p className="text-xs text-muted mt-0.5">{subtitle}</p>}
          </div>
          {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
        </header>
      )}
      <div className={padded ? "px-4 pb-4" : ""}>{children}</div>
    </section>
  );
}

export function Stat({ label, value, tone, hint, testId }: { label: string; value: ReactNode; tone?: Tone; hint?: ReactNode; testId?: string }) {
  return (
    <div className="card px-4 py-3" data-testid={testId}>
      <div className="text-[11px] font-bold tracking-[0.12em] uppercase text-muted">{label}</div>
      <div className={clsx("text-[28px] leading-8 font-bold mono mt-1", tone && TONE_CLASS[tone])}>{value}</div>
      {hint && <div className="text-xs text-muted mt-1">{hint}</div>}
    </div>
  );
}

export const Skeleton = ({ className }: { className?: string }) => <div className={clsx("skeleton", className ?? "h-6 w-full")} aria-hidden />;

export function EmptyState({ title, children, icon, action }: { title: string; children?: ReactNode; icon?: ReactNode; action?: ReactNode }) {
  return (
    <div className="card-flat px-6 py-10 text-center grid gap-2 justify-items-center" role="status">
      {icon && <div className="text-muted">{icon}</div>}
      <h3 className="font-bold">{title}</h3>
      {children && <div className="text-muted max-w-prose text-[13px]">{children}</div>}
      {action}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const msg = error instanceof Error ? error.message : "Something went wrong.";
  return (
    <div className="card-flat px-5 py-4 border-coral" role="alert" style={{ borderColor: "var(--coral)" }}>
      <div className="flex items-start gap-3">
        <XCircle className="tone-coral shrink-0 mt-0.5" size={18} aria-hidden />
        <div className="min-w-0 grid gap-1">
          <div className="font-bold tone-coral">Request failed</div>
          <div className="text-[13px] break-words">{msg}</div>
          {onRetry && <div><Button size="sm" onClick={onRetry}>Retry</Button></div>}
        </div>
      </div>
    </div>
  );
}

export function ProgressBar({ value, max, label, tone = "teal" }: { value: number; max: number; label: string; tone?: Tone }) {
  const pct = max > 0 ? Math.min(100, Math.round((value / max) * 100)) : 0;
  return (
    <div role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={max} aria-valuenow={value} className="h-2 rounded-full bg-raised overflow-hidden border border-line">
      <div className={clsx("h-full t-fast", TONE_CLASS[tone])} style={{ width: `${pct}%`, background: "currentColor" }} />
    </div>
  );
}

/** Stacked bar showing verified / failed / inconclusive / not executed against the real denominator. */
export function CoverageBar({ passed, failed, inconclusive, notExecuted, total }: { passed: number; failed: number; inconclusive: number; notExecuted: number; total: number }) {
  const seg = (n: number) => (total > 0 ? (n / total) * 100 : 0);
  return (
    <div>
      <div className="flex h-3 rounded-full overflow-hidden border border-line bg-raised" role="img"
        aria-label={`${passed} passed, ${failed} failed, ${inconclusive} inconclusive, ${notExecuted} not executed, of ${total} expected assertions`}>
        <div style={{ width: `${seg(passed)}%`, background: "var(--teal)" }} />
        <div style={{ width: `${seg(failed)}%`, background: "var(--coral)" }} />
        <div style={{ width: `${seg(inconclusive)}%`, background: "var(--amber)", backgroundImage: "repeating-linear-gradient(45deg,transparent 0 4px,rgba(0,0,0,.25) 4px 6px)" }} />
        <div style={{ width: `${seg(notExecuted)}%`, background: "var(--border)" }} />
      </div>
      <ul className="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-xs text-muted">
        <li><span className="tone-teal font-bold">■</span> Pass {passed}</li>
        <li><span className="tone-coral font-bold">■</span> Fail {failed}</li>
        <li><span className="tone-amber font-bold">▨</span> Inconclusive {inconclusive}</li>
        <li><span className="font-bold">□</span> Not executed {notExecuted}</li>
        <li className="ml-auto">of {total} expected assertions</li>
      </ul>
    </div>
  );
}

/* ───────────────────────────── overlays ───────────────────────────── */
export function Dialog({ open, onOpenChange, title, description, children, wide }: {
  open: boolean; onOpenChange: (o: boolean) => void; title: string; description?: string; children: ReactNode; wide?: boolean;
}) {
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/60 backdrop-blur-[2px]" />
        <DialogPrimitive.Content
          className={clsx("card enter fixed z-50 left-1/2 top-[8vh] -translate-x-1/2 w-[min(94vw,var(--w))] max-h-[84vh] overflow-auto p-5 scroll-thin")}
          style={{ ["--w" as string]: wide ? "880px" : "560px" }}
        >
          <div className="flex items-start justify-between gap-4 mb-3">
            <div>
              <DialogPrimitive.Title className="text-base font-bold">{title}</DialogPrimitive.Title>
              <DialogPrimitive.Description className="text-xs text-muted mt-0.5">{description ?? " "}</DialogPrimitive.Description>
            </div>
            <DialogPrimitive.Close asChild><Button variant="ghost" size="sm" aria-label="Close dialog"><X size={16} aria-hidden /></Button></DialogPrimitive.Close>
          </div>
          {children}
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}

export function Tip({ label, children }: { label: string; children: ReactNode }) {
  return (
    <TooltipPrimitive.Provider delayDuration={250}>
      <TooltipPrimitive.Root>
        <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
        <TooltipPrimitive.Portal>
          <TooltipPrimitive.Content sideOffset={6} className="z-[60] card px-2.5 py-1.5 text-xs max-w-xs">{label}</TooltipPrimitive.Content>
        </TooltipPrimitive.Portal>
      </TooltipPrimitive.Root>
    </TooltipPrimitive.Provider>
  );
}

/* ───────────────────────────── terminal card ───────────────────────────── */
export function Terminal({ lines, title = "terminal", prompt = "$" }: { lines: string[]; title?: string; prompt?: string | null }) {
  const [copied, setCopied] = useState(false);
  const text = lines.join("\n");
  return (
    <div className="card-flat overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-line text-[11px] uppercase tracking-widest text-muted">
        <span>{title}</span>
        <button
          className="t-fast inline-flex items-center gap-1 hover:text-ink"
          onClick={() => {
            void navigator.clipboard?.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1600); });
          }}
          aria-label="Copy to clipboard"
        >
          {copied ? <Check size={12} aria-hidden /> : <Copy size={12} aria-hidden />} {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="m-0 p-3 overflow-auto scroll-thin whitespace-pre-wrap break-words">
        {lines.map((l, i) => (
          <div key={i}>{prompt && !l.startsWith("--") && !l.startsWith(" ") ? <span className="tone-teal select-none">{prompt} </span> : null}{l}</div>
        ))}
      </pre>
    </div>
  );
}
