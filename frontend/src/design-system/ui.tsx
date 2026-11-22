import * as DialogPrimitive from "@radix-ui/react-dialog";
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import clsx from "clsx";
import {
  AlertTriangle, Ban, Check, CheckCircle2, CircleDashed, Copy, HelpCircle, Info, Loader2, Radio, ShieldAlert, ShieldCheck, X, XCircle,
} from "lucide-react";
import { forwardRef, useState, type ButtonHTMLAttributes, type ReactNode } from "react";

/* ───────────────────────────── brand ───────────────────────────── */
export function Logo({ size = 18 }: { size?: number; compact?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2 text-ink" aria-label="RLS Sentinel">
      <svg width={size} height={size} viewBox="0 0 20 20" role="img" aria-hidden="true">
        <ellipse cx="10" cy="4.5" rx="6.5" ry="2.5" fill="none" stroke="var(--muted)" strokeWidth="1.4" />
        <path d="M3.5 4.5v11c0 1.4 2.9 2.5 6.5 2.5s6.5-1.1 6.5-2.5v-11" fill="none" stroke="var(--muted)" strokeWidth="1.4" />
        <path d="M7 11.2l2.1 2.1L13.4 9" fill="none" stroke="var(--blue)" strokeWidth="1.6" strokeLinecap="square" />
      </svg>
      <span className="font-semibold text-[13px] whitespace-nowrap">RLS Sentinel</span>
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

export const DemoTag = () => <Lozenge tone="amber" title="Synthetic bundled fixture data">Demo data</Lozenge>;

/* ───────────────────────────── controls ───────────────────────────── */
type BtnProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" | "danger"; size?: "sm" | "md"; loading?: boolean };
export const Button = forwardRef<HTMLButtonElement, BtnProps>(function Button({ variant = "secondary", size = "md", loading, className, children, disabled, ...rest }, ref) {
  return (
    <button
      ref={ref}
      disabled={disabled || loading}
      className={clsx(
        "t-fast inline-flex items-center justify-center gap-1.5 rounded-[3px] font-medium border select-none whitespace-nowrap disabled:opacity-50 disabled:cursor-not-allowed",
        size === "sm" ? "h-7 px-2.5 text-[12px]" : "h-8 px-3 text-[12.5px]",
        variant === "primary" && "bg-primary text-[var(--on-accent)] border-primary hover:brightness-110",
        variant === "secondary" && "bg-raised text-ink border-line hover:bg-hover",
        variant === "ghost" && "bg-transparent text-muted border-transparent hover:bg-hover hover:text-ink",
        variant === "danger" && "bg-transparent text-coral border-[color-mix(in_srgb,var(--coral)_50%,transparent)] hover:bg-hover",
        className,
      )}
      {...rest}
    >
      {loading && <Loader2 size={13} className="animate-spin" aria-hidden />}
      {children}
    </button>
  );
});

export function Field({ label, hint, children, htmlFor }: { label: string; hint?: ReactNode; children: ReactNode; htmlFor?: string }) {
  return (
    <div className="grid gap-1 content-start">
      <label htmlFor={htmlFor} className="text-[12px] text-muted">{label}</label>
      {children}
      {hint && <p className="text-[11.5px] text-muted">{hint}</p>}
    </div>
  );
}

export const inputCls = "w-full rounded-[3px] bg-low border border-line px-2 h-7 text-[12.5px] text-ink placeholder:text-muted t-fast focus:border-sky";
export const Input = forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(function Input({ className, ...p }, ref) {
  return <input ref={ref} className={clsx(inputCls, className)} {...p} />;
});
export const Select = forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(function Select({ className, ...p }, ref) {
  return <select ref={ref} className={clsx(inputCls, "pr-6", className)} {...p} />;
});

/* ───────────────────────────── surfaces ───────────────────────────── */
export function Card({ title, subtitle, actions, children, className, padded = true, id }: {
  title?: ReactNode; subtitle?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; padded?: boolean; id?: string;
}) {
  return (
    <section id={id} className={clsx("card", className)} aria-labelledby={id ? `${id}-t` : undefined}>
      {(title || actions) && (
        <header className="panel-head justify-between">
          <div className="min-w-0 flex items-baseline gap-2">
            {title && <h2 id={id ? `${id}-t` : undefined} className="text-[12.5px] font-semibold text-ink whitespace-nowrap">{title}</h2>}
            {subtitle && <p className="text-[11.5px] text-muted truncate">{subtitle}</p>}
          </div>
          {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
        </header>
      )}
      <div className={padded ? "p-3" : ""}>{children}</div>
    </section>
  );
}

export function Stat({ label, value, tone, hint, testId }: { label: string; value: ReactNode; tone?: Tone; hint?: ReactNode; testId?: string }) {
  return (
    <div className="card px-3 py-2" data-testid={testId}>
      <div className="text-[11.5px] text-muted">{label}</div>
      <div className={clsx("text-[20px] leading-7 font-medium mono", tone && TONE_CLASS[tone])}>{value}</div>
      {hint && <div className="text-[11.5px] text-muted">{hint}</div>}
    </div>
  );
}

export const Skeleton = ({ className }: { className?: string }) => <div className={clsx("skeleton", className ?? "h-6 w-full")} aria-hidden />;

export function EmptyState({ title, children, icon, action }: { title: string; children?: ReactNode; icon?: ReactNode; action?: ReactNode }) {
  return (
    <div className="card-flat px-5 py-8 text-center grid gap-1.5 justify-items-center" role="status">
      {icon && <div className="text-muted">{icon}</div>}
      <h3 className="font-semibold text-[13px]">{title}</h3>
      {children && <div className="text-muted max-w-prose text-[12.5px]">{children}</div>}
      {action}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const msg = error instanceof Error ? error.message : "Something went wrong.";
  return (
    <div className="card-flat px-4 py-3" role="alert" style={{ borderLeft: "2px solid var(--coral)" }}>
      <div className="flex items-start gap-2.5">
        <XCircle className="tone-coral shrink-0 mt-0.5" size={15} aria-hidden />
        <div className="min-w-0 grid gap-1">
          <div className="font-semibold tone-coral">Request failed</div>
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
    <div role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={max} aria-valuenow={value} className="h-1.5 rounded-[1px] bg-raised overflow-hidden">
      <div className={clsx("h-full t-fast", TONE_CLASS[tone])} style={{ width: `${pct}%`, background: "currentColor" }} />
    </div>
  );
}

/** Stacked bar showing verified / failed / inconclusive / not executed against the real denominator. */
export function CoverageBar({ passed, failed, inconclusive, notExecuted, total }: { passed: number; failed: number; inconclusive: number; notExecuted: number; total: number }) {
  const seg = (n: number) => (total > 0 ? (n / total) * 100 : 0);
  return (
    <div>
      <div className="flex h-2.5 rounded-[2px] overflow-hidden bg-raised" role="img"
        aria-label={`${passed} passed, ${failed} failed, ${inconclusive} inconclusive, ${notExecuted} not executed, of ${total} expected assertions`}>
        <div style={{ width: `${seg(passed)}%`, background: "var(--teal)" }} />
        <div style={{ width: `${seg(failed)}%`, background: "var(--coral)" }} />
        <div style={{ width: `${seg(inconclusive)}%`, background: "var(--amber)", backgroundImage: "repeating-linear-gradient(45deg,transparent 0 3px,rgba(0,0,0,.28) 3px 5px)" }} />
        <div style={{ width: `${seg(notExecuted)}%`, background: "var(--surface-hover)" }} />
      </div>
      <ul className="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-[12px] text-muted">
        <li><span className="tone-teal">■</span> Pass {passed}</li>
        <li><span className="tone-coral">■</span> Fail {failed}</li>
        <li><span className="tone-amber">▨</span> Inconclusive {inconclusive}</li>
        <li><span>□</span> Not executed {notExecuted}</li>
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
        <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/55" />
        <DialogPrimitive.Content
          className={clsx("card enter fixed z-50 left-1/2 top-[8vh] -translate-x-1/2 w-[min(94vw,var(--w))] max-h-[84vh] overflow-auto scroll-thin")}
          style={{ ["--w" as string]: wide ? "880px" : "560px" }}
        >
          <div className="panel-head justify-between !py-1.5">
            <div className="min-w-0">
              <DialogPrimitive.Title className="text-[13px] font-semibold">{title}</DialogPrimitive.Title>
              <DialogPrimitive.Description className="text-[11.5px] text-muted">{description ?? " "}</DialogPrimitive.Description>
            </div>
            <DialogPrimitive.Close asChild><Button variant="ghost" size="sm" aria-label="Close dialog"><X size={14} aria-hidden /></Button></DialogPrimitive.Close>
          </div>
          <div className="p-4">{children}</div>
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
          <TooltipPrimitive.Content sideOffset={6} className="z-[60] card px-2 py-1 text-[12px] max-w-xs">{label}</TooltipPrimitive.Content>
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
      <div className="flex items-center justify-between px-2.5 h-7 border-b border-line bg-raised text-[11.5px] text-muted">
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
      <pre className="m-0 px-3 py-2 overflow-auto scroll-thin whitespace-pre-wrap break-words">
        {lines.map((l, i) => (
          <div key={i}>{prompt && !l.startsWith("--") && !l.startsWith(" ") ? <span className="tone-teal select-none">{prompt} </span> : null}{l}</div>
        ))}
      </pre>
    </div>
  );
}
