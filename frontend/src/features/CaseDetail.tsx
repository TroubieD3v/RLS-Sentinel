import { Link } from "react-router-dom";
import type { CaseRow } from "@/api/types";
import { Lozenge, ProvenanceLozenge, StatusLozenge } from "@/design-system/ui";
import { SqlBlock } from "@/lib/sql";

const yn = (v: boolean | null | undefined) => (v == null ? "—" : v ? "yes" : "no");

export function CaseDetail({ c, findingIds }: { c: CaseRow; findingIds?: string[] }) {
  const r = c.evidence.raw;
  return (
    <div className="grid gap-3 text-[13px]" data-testid="case-detail">
      <div className="flex items-center gap-2 flex-wrap">
        <StatusLozenge status={c.status} />
        <ProvenanceLozenge kind="runtime" />
        {c.evidence.identity_adapter !== "postgres_roles" && <Lozenge tone="amber">Synthetic identity · not authentication</Lozenge>}
      </div>
      <h3 className="mono font-bold break-all">{c.case_id}</h3>
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
        <dt className="text-muted">Operation</dt><dd>{c.operation} {c.resource ?? ""}</dd>
        <dt className="text-muted">Expected</dt><dd className="mono">{c.expected}</dd>
        <dt className="text-muted">Observed</dt><dd className="mono">{c.observed}{c.sqlstate ? ` (SQLSTATE ${c.sqlstate})` : ""}</dd>
        <dt className="text-muted">Deciding gate</dt><dd className="mono">{r.gate}{r.gate === "GRANT" ? " — SQL privilege, RLS not exercised" : r.gate === "RLS" ? " — row-level security" : ""}</dd>
        <dt className="text-muted">Actor context</dt><dd className="mono">session_user={r.session_user ?? "?"} · current_user={r.current_user ?? "?"}</dd>
        <dt className="text-muted">Role flags</dt><dd className="mono">superuser={yn(r.role_superuser)} · bypassrls={yn(r.role_bypassrls)} · bypass={r.bypass_reason ?? "none"}</dd>
        <dt className="text-muted">Table RLS</dt><dd className="mono">enabled={yn(r.rls_enabled)} · forced={yn(r.rls_forced)} · applies={yn(r.rls_applies)}</dd>
        <dt className="text-muted">SQL privilege</dt><dd className="mono">{yn(r.privilege_ok)}</dd>
        <dt className="text-muted">Rows observed</dt><dd className="mono">{c.evidence.observed_count ?? "—"} <span className="text-muted">(contents not retained)</span></dd>
        <dt className="text-muted">Baseline</dt>
        <dd>target exists: <b>{yn(c.evidence.baseline.target_exists)}</b>{c.evidence.baseline.authorized_control ? <> · positive control <span className="mono">{c.evidence.baseline.authorized_control}</span> ({c.evidence.baseline.authorized_control_status})</> : " · no positive control declared"}</dd>
      </dl>
      <p className="card-flat p-3">{c.evidence.explanation}</p>
      {r.applicable_policies.length > 0 && (
        <div>
          <div className="text-xs font-bold uppercase tracking-wide text-muted mb-1">Policies applicable to this role and command</div>
          <ul className="flex flex-wrap gap-1.5">
            {r.applicable_policies.map((p) => (
              <li key={p.name}><Lozenge tone={p.permissive ? "violet" : "blue"}>{p.permissive ? "permissive" : "restrictive"} {p.command}</Lozenge> <span className="mono">{p.name}</span></li>
            ))}
          </ul>
        </div>
      )}
      <div>
        <div className="text-xs font-bold uppercase tracking-wide text-muted mb-1">Sanitized SQL (identifiers masked, parameters bound)</div>
        <SqlBlock text={c.evidence.sql} label="Executed statement" />
      </div>
      <p className="text-xs text-muted mono break-all">environment {c.evidence.environment_hash} · {c.evidence.record_identifier_masked ? "identifiers masked" : "identifiers visible"} · {c.duration_ms ?? "?"} ms</p>
      {findingIds && findingIds.length > 0 && (
        <div className="flex gap-2 flex-wrap">{findingIds.map((id) => <Link key={id} to={`/findings?id=${id}`} className="text-sky underline text-xs">Open linked finding →</Link>)}</div>
      )}
    </div>
  );
}
