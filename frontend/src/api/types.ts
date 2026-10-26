export type Status = "PASS" | "FAIL" | "INCONCLUSIVE" | "ERROR" | "UNSUPPORTED" | "SKIPPED";
export type EvidenceClass = "CONFIRMED_VIOLATION" | "CONFIGURATION_RISK" | "INCONCLUSIVE" | "EXPECTED_DENIAL" | "VERIFIED_ALLOW" | "UNSUPPORTED";
export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational" | "Needs triage";
export type Lifecycle = "open" | "triaged" | "accepted_risk" | "false_positive" | "fixed" | "needs_info";

export interface Pagination { total: number; offset: number; limit: number; returned: number }
export interface Envelope<T> { data: T; meta: Record<string, unknown> & { pagination?: Pagination } }

export interface Health {
  status: string; version: string; ruleset: string; auth: string; metadata_store: string; source_database_mutation: string;
  lab: { available: boolean; backend: string; detail: string; running: boolean };
}

export interface Fixture {
  name: string; title: string; description: string; variants: string[]; roles: string[]; tags: string[]; min_pg_major: number;
  expected_outcomes: Record<string, { fail?: string[]; inconclusive?: string[] }>;
}
export interface FixtureDetail extends Fixture { specs: Record<string, string>; sql: Record<string, Record<string, string>> }

export interface Coverage {
  expected_assertions: number; executed_valid_context: number; passed: number; failed: number; inconclusive: number; errors: number;
  unsupported: number; skipped: number; not_executed: number; decided: number; verified_coverage_pct: number; rls_exercised: number;
  grant_gate_only: number; synthetic_identity_cases: number; notes: string[];
}

export interface Progress { stage?: string; message?: string; done?: number; total?: number; case?: string; observed?: string }
export interface Isolation {
  data_digest_before: string; data_digest_after: string; no_fixture_drift: boolean | null; source_database_touched: boolean;
  harness_superuser: boolean | null; harness_bypassrls: boolean | null; statements_executed: number;
}

export interface RunMeta {
  id: string; workspace_id: string; snapshot_id: string | null; spec_id: string | null; job_id: string | null; kind: "lab" | "catalog" | "whatif_sandbox";
  fixture: string | null; variant: string | null; environment_mode: string; started_at: string; completed_at: string | null;
  status: "queued" | "running" | "completed" | "failed" | "cancelled"; version_info: Record<string, string | number | null>;
  coverage: Partial<Coverage>; error: string | null;
  progress?: Progress | null;
  summary?: { coverage: Coverage; panel: string; isolation: Isolation; findings: number; errors: string[]; info: Record<string, unknown> } | null;
}

export interface EvidenceRef { kind: "case" | "catalog" | "spec" | "diff"; ref: string; summary: string; provenance: string }
export interface Finding {
  id: string; fingerprint: string; rule_id: string; title: string; severity: Severity; severity_rationale: string; evidence_class: EvidenceClass;
  provenance: string[]; confidence: string; subject: string; summary: string; why_it_matters: string; expected: string | null; observed: string | null;
  evidence: EvidenceRef[]; case_ids: string[]; objects: Record<string, unknown>; reproduction: string[]; remediation: string; references: string[];
  limitations: string; verified_by: string; location: { path: string; line?: number } | null; lifecycle_state: Lifecycle; reviewer_note: string;
  suppressed: boolean; suppression: Record<string, string> | null; related: string[]; run_id?: string;
}

export interface MatrixCell { case_id: string; expected: string; observed: string | null; status: string; state: string; gate?: string; sqlstate?: string | null; finding_class?: string }
export interface Matrix {
  rows: { actor: string; db_role: string; tenant: string | null; cells: Record<string, MatrixCell[]> }[];
  columns: { key: string; operation: string; table: string | null; resource: string | null; via: string | null; columns: string[]; tenant: string | null }[];
  totals: Record<string, number>; state_labels: Record<string, string>; executed: boolean; denominator: number;
}

export interface CaseRow {
  case_id: string; actor: string; resource: string | null; operation: string; expected: string; observed: string; status: Status; sqlstate: string | null;
  environment_fingerprint: string; duration_ms: number | null; table?: string | null; via?: string | null;
  evidence: {
    sql: string; explanation: string; notes: string[]; observed_count: number | null; environment_hash: string; identity_adapter: string;
    authentication_verified: boolean; record_identifier_masked: boolean; row_contents_retained: boolean;
    baseline: { target_exists: boolean | null; authorized_control: string | null; authorized_control_status: string | null };
    raw: {
      gate: string; session_user: string | null; current_user: string | null; role_superuser: boolean | null; role_bypassrls: boolean | null; rls_enabled: boolean | null;
      rls_forced: boolean | null; rls_applies: boolean | null; bypass_reason: string | null; privilege_ok: boolean | null; message: string | null;
      applicable_policies: { name: string; command: string; permissive: boolean }[]; row_count: number | null;
    };
  };
}

export interface GNode { id: string; type: string; label: string; lane: number; order: number; props: Record<string, unknown>; source: string | null }
export interface GEdge {
  id: string; source: string; target: string; type: string; label: string; style: "catalog" | "static" | "violation" | "verified";
  evidence_type: string; confidence: string; explanation: string; required_conditions: string[]; source_ref: string | null;
}
export interface GraphData { nodes: GNode[]; edges: GEdge[]; truncated: boolean; omitted: Record<string, number>; totals: Record<string, number>; cycles: string[][] }

export interface Column { name: string; type: string; not_null: boolean; tenant_candidate: boolean; position: number }
export interface Provenance { path?: string | null; line?: number | null; ref?: string | null }
export interface TableRec {
  schema: string; name: string; kind: string; owner: string; rls_enabled: boolean; rls_forced: boolean; row_estimate: number | null;
  columns: Column[]; primary_key: string[]; options: Record<string, string | boolean>; view_definition: string | null; view_depends_on: string[];
  triggers: unknown[]; provenance: Provenance;
}
export interface PolicyRec {
  name: string; table: string; command: string; roles: string[]; permissive: boolean; using_expr: string | null; check_expr: string | null;
  deps: { columns: string[]; functions: string[]; relations: string[] }; provenance: Provenance;
}
export interface RoleRec { name: string; superuser: boolean; bypassrls: boolean; login: boolean; inherit: boolean; system: boolean }
export interface GrantRec { object_type: string; object: string; grantee: string; privilege: string; grantable: boolean }
export interface FunctionRec {
  schema: string; name: string; identity_args: string; owner: string; security_definer: boolean; config: string[]; language: string; public_execute: boolean;
}
export interface Snapshot {
  postgres_version: string; database: string; schema_hash: string; created_at: string;
  source: { kind: string; alias: string; mode: string; display_target?: string };
  schemas: { name: string; owner: string }[]; tables: TableRec[]; policies: PolicyRec[]; roles: RoleRec[]; memberships: { role: string; member: string }[];
  grants: GrantRec[]; functions: FunctionRec[];
  coverage: {
    postgres_version: string; scan_mode: string; schemas_seen: number; tables_seen: number; policies_seen: number; roles_seen: number; functions_seen: number;
    source_row_data_collected: boolean; catalog_objects_skipped: unknown[]; runtime_tests_executed: boolean; coverage_notes: string[];
  };
}

export interface HistoryRow {
  run_id: string; kind: string; started_at: string; status: string; fixture: string | null; variant: string | null; environment_mode: string;
  schema_hash: string | null; expected: number; passed: number; failed: number; inconclusive: number; verified_coverage_pct: number; findings: number;
  by_evidence_class: Record<string, number>;
}

export interface Suggestion { id: string; finding_ids: string[]; rule_id: string; title: string; sql: string; rationale: string; caveats: string[] }
export interface CaseDelta { case_id: string; actor: string; operation: string; expected: string; before: string; after: string; kind: string; detail: string }
export interface WhatIfResult {
  verdict: string; verdict_text: string; summary: Record<string, number>; deltas: CaseDelta[]; apply_error: string | null; applied_statements: number;
  baseline_coverage: Coverage; sandbox_coverage: Coverage; baseline_schema_hash: string; sandbox_schema_hash: string; postgres_version: string; duration_s: number;
  snapshot_diff: { changes: { category: string; kind: string; subject: string; summary: string; risk: string; textual_only: boolean }[]; summary: Record<string, number> } | null;
  resolved_findings: Finding[]; new_findings: Finding[];
}
export interface WhatIf {
  id: string; status: string; verdict: string; error: string | null; banner: string; baseline_run_id: string; draft_sql: string; created_at: string;
  result: WhatIfResult | null;
}

export interface SpecValidation {
  valid: boolean; issues: { level: string; path: string; message: string }[]; checksum?: string; counts?: Record<string, number>;
  normalized?: {
    actors: { id: string; pg_role: string; tenant: string | null; kind: string }[]; resources: { id: string; table: string }[];
    expectations: { id: string; actor: string; operation: string; resource?: string; table?: string; expected: string }[]; privileges: unknown[];
  } & Record<string, unknown>;
}

export interface ConnectionProfile {
  id: string; target_alias: string; mode: string; display_target: string | null; pg_major_version: number | null;
  secret: { stored: boolean; reference: string }; last_connection_status: string | null; created_at: string;
}
export interface ConnDiagnostics {
  reachable: boolean; postgres_version: string; database: string; inspector_role: string; is_superuser: boolean; bypasses_rls: boolean;
  read_only_session_enforced: boolean; can_read_pg_policy: boolean; supported_major: boolean; warnings: string[]; risk_notice: string; mode: string;
}
export interface Problem { title: string; status: number; detail: string; code: string; issues?: { path: string; message: string; level: string }[] }
export interface RuleInfo { id: string; title: string; description: string; minimum_evidence: string; category: string; references: string[]; remediation: string }
export interface AuditEvent { id: string; actor: string; event_type: string; target: string; timestamp: string; detail: Record<string, unknown> }
export interface Suppression {
  id: string; rule_id: string; scope: string; reason: string; owner: string; reviewer: string; expires_at: string; active: boolean; revoked_at: string | null;
}
