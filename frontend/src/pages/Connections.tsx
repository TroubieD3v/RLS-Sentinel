import { useQueryClient } from "@tanstack/react-query";
import { DatabaseZap, Lock, PlugZap, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "@/api/client";
import type { ConnDiagnostics, ConnectionProfile } from "@/api/types";
import { describeError, PageHeader } from "@/components/Shell";
import { Button, Card, EmptyState, Field, Input, Lozenge, ModeBadge, Select, Skeleton, Terminal } from "@/design-system/ui";
import { FixturePicker } from "@/features/RunPanel";
import { qk, useConnections, useHealth } from "@/lib/queries";
import { timeAgo } from "@/lib/format";
import { streamEvents } from "@/api/client";
import { useApp } from "@/state/app";

const INSPECTOR_SQL = [
  "-- run once as an administrator on the database you are authorized to audit",
  "CREATE ROLE sentinel_inspector LOGIN PASSWORD '<generate-a-strong-password>' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;",
  "GRANT CONNECT ON DATABASE <your_db> TO sentinel_inspector;",
  "-- pg_catalog is readable by every role; no table privileges are needed (row data is never read)",
  "ALTER ROLE sentinel_inspector SET default_transaction_read_only = on;",
  "ALTER ROLE sentinel_inspector SET statement_timeout = '8s';",
];

export default function Connections() {
  const health = useHealth();
  const conns = useConnections();
  const qc = useQueryClient();
  const { toast } = useApp();
  const [alias, setAlias] = useState("");
  const [dsn, setDsn] = useState("");
  const [envRef, setEnvRef] = useState("");
  const [mode, setMode] = useState<"session" | "env">("session");
  const [diag, setDiag] = useState<ConnDiagnostics | null>(null);
  const [busy, setBusy] = useState<"" | "test" | "save">("");
  const [fx, setFx] = useState({ fixture: "", variant: "vulnerable" });
  const [scanState, setScanState] = useState<string>("");

  const body = () => (mode === "env" ? { secret_ref: `env:${envRef.trim()}` } : { dsn });
  const valid = alias.trim() && (mode === "env" ? /^[A-Za-z_][A-Za-z0-9_]*$/.test(envRef.trim()) : dsn.trim().length > 8);

  const scan = async (payload: Record<string, unknown>, label: string) => {
    setScanState(`${label}: starting…`);
    try {
      const r = await api<{ job_id: string }>("/scans", { method: "POST", body: payload });
      const ac = new AbortController();
      await streamEvents(`/jobs/${r.data.job_id}/events`, (e) => {
        if (e.type === "progress") setScanState(`${label}: ${String(e.data.message ?? e.data.stage ?? "working")}`);
        if (e.type === "failed") setScanState(`${label}: failed — ${String(e.data.error)}`);
        if (e.type === "completed") setScanState(`${label}: completed`);
      }, ac.signal);
      void qc.invalidateQueries({ queryKey: qk.runs });
      toast("teal", `${label} completed. Open the Schema or Policies page.`);
    } catch (e) { setScanState(`${label}: ${describeError(e)}`); toast("coral", describeError(e)); }
  };

  return (
    <div className="grid gap-4">
      <PageHeader kicker="Authorized connections & workspaces" title="Connections" subtitle="Two modes, never mixed: read-only catalog inspection of an authorized source, and mutating verification in a disposable lab." />
      <div className="grid md:grid-cols-2 gap-4">
        <Card title="Read-only source" actions={<ModeBadge mode="READ-ONLY SOURCE" />} id="mode-source">
          <ul className="text-[13px] grid gap-1.5 list-disc pl-4">
            <li>Only bounded <span className="mono">pg_catalog</span> SELECTs inside a READ ONLY transaction; no DDL, DML or row data.</li>
            <li>Superuser inspector accounts are refused; targets must be on the server-side allowlist (default: loopback only).</li>
            <li>The connection string is write-only: held in server memory for this session, never stored, logged or returned.</li>
          </ul>
        </Card>
        <Card title="Disposable lab" actions={<ModeBadge mode="DISPOSABLE LAB" />} id="mode-lab">
          <ul className="text-[13px] grid gap-1.5 list-disc pl-4">
            <li>All INSERT/UPDATE/DELETE/UPSERT and What-if edits run only in a throw-away PostgreSQL instance and are rolled back.</li>
            <li>Tests run as a non-superuser harness that SETs ROLE into membership-authorized actor roles.</li>
            <li data-testid="lab-status">Backend: {health.data ? (health.data.lab.available ? <><Lozenge tone="teal">{health.data.lab.backend}</Lozenge> <span className="text-muted">{health.data.lab.detail}</span></> : <Lozenge tone="coral">unavailable</Lozenge>) : "checking…"}</li>
          </ul>
        </Card>
      </div>

      <div className="grid xl:grid-cols-2 gap-4 items-start">
        <Card title="Add a live source" subtitle="Authorized, least-privilege, catalog-only" id="add-source">
          <form className="grid gap-3" onSubmit={(e) => e.preventDefault()}>
            <Field label="Alias" htmlFor="c-alias"><Input id="c-alias" value={alias} onChange={(e) => setAlias(e.target.value)} placeholder="staging-app-db" /></Field>
            <Field label="Secret handling" htmlFor="c-mode" hint={mode === "session" ? "Session-only: kept in server memory until restart. No encrypted vault is offered because no key management is configured." : "Resolved from the server environment at use time; the value never reaches the browser."}>
              <Select id="c-mode" value={mode} onChange={(e) => setMode(e.target.value as "session" | "env")}><option value="session">Enter connection string (session-only)</option><option value="env">Reference a server environment variable</option></Select></Field>
            {mode === "session" ? (
              <Field label="Connection string" htmlFor="c-dsn"><Input id="c-dsn" type="password" autoComplete="off" value={dsn} onChange={(e) => setDsn(e.target.value)} placeholder="postgresql://sentinel_inspector:…@host:5432/app" data-testid="dsn-input" /></Field>
            ) : (
              <Field label="Environment variable name" htmlFor="c-env"><Input id="c-env" value={envRef} onChange={(e) => setEnvRef(e.target.value)} placeholder="SENTINEL_DATABASE_URL" /></Field>
            )}
            <div className="flex gap-2 flex-wrap">
              <Button loading={busy === "test"} disabled={!valid} data-testid="test-conn" onClick={() => {
                setBusy("test"); setDiag(null);
                api<ConnDiagnostics>("/connections/test", { method: "POST", body: body() }).then((r) => setDiag(r.data)).catch((e) => toast("coral", describeError(e))).finally(() => setBusy(""));
              }}><PlugZap size={14} aria-hidden /> Test connection</Button>
              <Button variant="primary" loading={busy === "save"} disabled={!valid} onClick={() => {
                setBusy("save");
                api<ConnectionProfile>("/connections", { method: "POST", body: { alias, ...body() } })
                  .then(() => { toast("teal", "Connection registered (secret not stored)."); setDsn(""); setAlias(""); void qc.invalidateQueries({ queryKey: qk.connections }); })
                  .catch((e) => toast("coral", describeError(e))).finally(() => setBusy(""));
              }}><Lock size={14} aria-hidden /> Register</Button>
            </div>
            {diag && (
              <div className="card-flat p-3 grid gap-1.5 text-[13px]" role="status" data-testid="diagnostics">
                <div className="flex gap-2 items-center flex-wrap"><Lozenge tone="teal">Reachable</Lozenge><span className="mono">PostgreSQL {diag.postgres_version}</span><span className="mono text-muted">{diag.database} as {diag.inspector_role}</span></div>
                <div className="flex gap-2 flex-wrap">
                  {diag.read_only_session_enforced ? <Lozenge tone="teal">Read-only enforced</Lozenge> : <Lozenge tone="amber">Read-only unconfirmed</Lozenge>}
                  {diag.can_read_pg_policy ? <Lozenge tone="teal">pg_policy readable</Lozenge> : <Lozenge tone="amber">pg_policy not readable</Lozenge>}
                  {!diag.supported_major && <Lozenge tone="amber">Outside PG 15–18</Lozenge>}
                </div>
                {diag.warnings.map((w) => <p key={w} className="tone-amber">⚠ {w}</p>)}
                <p className="text-xs text-muted">{diag.risk_notice}</p>
              </div>
            )}
          </form>
        </Card>
        <div className="grid gap-4">
          <Card title="Least-privilege inspector" subtitle="Create this role on the source before connecting" id="least-priv"><Terminal title="psql · admin session" prompt={null} lines={INSPECTOR_SQL} /></Card>
          <Card title="Registered connections" id="conn-list">
            {conns.isLoading ? <Skeleton className="h-16" /> : (conns.data?.length ?? 0) === 0 ? <EmptyState title="No live sources registered" icon={<DatabaseZap />}>The disposable lab works without any connection: choose a bundled fixture below.</EmptyState> : (
              <ul className="grid gap-2">{conns.data!.map((c) => (
                <li key={c.id} className="card-flat p-3 flex items-center gap-3 flex-wrap" data-testid="conn-row">
                  <div className="min-w-0"><div className="font-bold">{c.target_alias}</div><div className="mono text-xs text-muted truncate">{c.display_target} · PG {c.pg_major_version ?? "?"} · secret: {c.secret.reference}</div>
                    <div className="text-xs text-muted">{c.last_connection_status} · {timeAgo(c.created_at)}</div></div>
                  <div className="ml-auto flex gap-2"><Button size="sm" onClick={() => void scan({ connection_id: c.id }, `Scan ${c.target_alias}`)}>Catalog scan</Button>
                    <Button size="sm" variant="ghost" aria-label={`Forget ${c.target_alias}`} onClick={() => void api(`/connections/${c.id}`, { method: "DELETE" }).then(() => qc.invalidateQueries({ queryKey: qk.connections }))}><Trash2 size={14} aria-hidden /></Button></div>
                </li>))}</ul>)}
          </Card>
        </div>
      </div>
      <Card title="Scan a disposable lab fixture (catalog only)" subtitle="Provision a throw-away database, read its catalog through the non-superuser harness login, run static rules" id="lab-scan">
        <div className="grid gap-3 max-w-3xl">
          <FixturePicker fixture={fx.fixture} variant={fx.variant} onChange={(f, v) => setFx({ fixture: f, variant: v })} />
          <div className="flex gap-3 items-center flex-wrap"><Button disabled={!fx.fixture || !health.data?.lab.available} onClick={() => void scan({ fixture: fx.fixture, variant: fx.variant }, `Lab scan ${fx.fixture}`)} data-testid="lab-scan">Run catalog scan</Button>
            <span className="text-xs text-muted mono" role="status">{scanState}</span>{scanState.endsWith("completed") && <Link className="text-sky underline text-xs" to="/schema">Open schema explorer →</Link>}</div>
        </div>
      </Card>
    </div>
  );
}
