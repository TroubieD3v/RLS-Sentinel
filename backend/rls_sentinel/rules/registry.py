"""Versioned rule catalogue: ids, titles, minimum evidence, remediation text and official references."""

from __future__ import annotations

from dataclasses import dataclass, field

DOC_RLS = "https://www.postgresql.org/docs/current/ddl-rowsecurity.html"
DOC_POLICY = "https://www.postgresql.org/docs/current/sql-createpolicy.html"
DOC_PG_POLICY = "https://www.postgresql.org/docs/current/catalog-pg-policy.html"
DOC_PG_POLICIES = "https://www.postgresql.org/docs/current/view-pg-policies.html"
DOC_VIEW = "https://www.postgresql.org/docs/current/sql-createview.html"
DOC_GRANT = "https://www.postgresql.org/docs/current/sql-grant.html"
DOC_FUNCTION = "https://www.postgresql.org/docs/current/sql-createfunction.html"
DOC_ALTER_TABLE = "https://www.postgresql.org/docs/current/sql-altertable.html"
DOC_ROLE_ATTR = "https://www.postgresql.org/docs/current/role-attributes.html"
DOC_SUPABASE = "https://supabase.com/docs/guides/database/postgres/row-level-security"


@dataclass(frozen=True)
class RuleMeta:
    id: str
    title: str
    description: str
    min_evidence: str
    default_level: str  # SARIF level: error | warning | note
    category: str
    references: tuple[str, ...] = field(default_factory=tuple)
    supports_static: bool = True
    supports_runtime: bool = False
    remediation: str = ""


RULES: dict[str, RuleMeta] = {r.id: r for r in [
    RuleMeta("RLS-001", "RLS disabled on an intended tenant-protected table",
             "Row-level security is not enabled on a table the expected-policy spec declares as protected. Existing policies, if any, are inactive and only SQL GRANTs apply.",
             "Table metadata + declared expectation", "warning", "configuration", (DOC_RLS, DOC_ALTER_TABLE), True, False,
             "ALTER TABLE <table> ENABLE ROW LEVEL SECURITY; then add explicit policies (RLS-enabled tables with no policy deny access by default)."),
    RuleMeta("RLS-002", "Excessively broad permissive policy",
             "A permissive policy whose expression is constant TRUE applies to roles that the spec expects to be tenant-bounded. Permissive policies are OR-ed, so one broad policy removes the tenant filter.",
             "Applicable policy + expected row boundary", "warning", "policy", (DOC_POLICY, DOC_RLS), True, True,
             "Replace the constant expression with a tenant-bounded predicate, or restrict the policy to the specific role that legitimately needs broad access."),
    RuleMeta("RLS-003", "Unintended PUBLIC role policy or grant",
             "A policy or table grant targets PUBLIC, i.e. every current and future role, on a protected table.",
             "Role scope + target exposure context", "warning", "exposure", (DOC_POLICY, DOC_GRANT), True, False,
             "Target an explicit role (TO app_user) instead of PUBLIC and REVOKE ... FROM PUBLIC."),
    RuleMeta("RLS-004", "Owner or BYPASSRLS execution path",
             "Superusers and BYPASSRLS roles skip row security entirely; a table owner skips it unless FORCE ROW LEVEL SECURITY is set. If such a role serves application traffic, policies are not evaluated.",
             "Effective actor privileges + concrete path", "error", "bypass", (DOC_RLS, DOC_ROLE_ATTR), True, True,
             "Do not run application sessions as the table owner or a BYPASSRLS role. Consider ALTER TABLE ... FORCE ROW LEVEL SECURITY for owner-run code paths."),
    RuleMeta("RLS-005", "INSERT / UPDATE missing or ineffective new-row guard",
             "A WITH CHECK expression is absent, constant TRUE or does not bind the tenant column, so a role can create or move rows into a tenant it does not belong to.",
             "DML-specific semantics / runtime test", "error", "policy", (DOC_POLICY,), True, True,
             "Add or tighten WITH CHECK so the new row satisfies the same tenant predicate as USING."),
    RuleMeta("RLS-006", "Cross-tenant SELECT visibility",
             "A role obtained a row that belongs to another tenant (runtime evidence under test roles).",
             "Runtime evidence under test roles", "error", "isolation", (DOC_RLS,), False, True,
             "Constrain every permissive SELECT policy with the tenant predicate; remove constant-TRUE policies."),
    RuleMeta("RLS-007", "Cross-tenant UPDATE/DELETE access",
             "A role modified or deleted a row that belongs to another tenant (controlled mutation test, rolled back).",
             "Controlled mutation test", "error", "isolation", (DOC_POLICY,), False, True,
             "Bound UPDATE/DELETE policies by the tenant predicate (USING) and new-row predicate (WITH CHECK)."),
    RuleMeta("RLS-008", "Privileged view exposure with owner-policy context",
             "A view without security_invoker runs with its owner's privileges; if the owner bypasses RLS on the base table, the view exposes rows across tenants.",
             "View metadata + role behavior test", "error", "view", (DOC_VIEW, DOC_RLS), True, True,
             "ALTER VIEW <view> SET (security_invoker = true) (PostgreSQL 15+), or move the tenant filter into the view and revoke direct access."),
    RuleMeta("RLS-009", "SECURITY DEFINER misuse candidate",
             "A SECURITY DEFINER function owned by a role that bypasses RLS on protected tables is executable by non-owner roles. Not every SECURITY DEFINER function is vulnerable; this is a candidate unless a runtime case confirms leakage.",
             "Function owner/grants/context + concrete behavior if claimed confirmed", "warning", "function", (DOC_FUNCTION,), True, True,
             "Prefer SECURITY INVOKER; if DEFINER is required, pin search_path, check the caller's tenant inside the function, and REVOKE EXECUTE FROM PUBLIC."),
    RuleMeta("RLS-010", "Unexpected GRANT or column privilege",
             "Effective SQL privileges differ from the privileges the spec expects for a role.",
             "Catalog + user-defined permission expectations", "warning", "grants", (DOC_GRANT,), True, True,
             "REVOKE the unexpected privilege (or update the expectation if the privilege is intended)."),
    RuleMeta("RLS-011", "Conflicting permissive/restrictive policies",
             "Permissive policies combine with OR and restrictive policies with AND; restrictive policies alone never grant access. A policy that is permissive where a restriction was intended (or the reverse) changes the effective boundary.",
             "Correct effective evaluation or inconclusive", "warning", "policy", (DOC_POLICY,), True, True,
             "Declare restrictions with CREATE POLICY ... AS RESTRICTIVE and keep at least one permissive policy per command that grants access."),
    RuleMeta("RLS-012", "Policy function missing privileges / recursion",
             "Evaluating a policy raised a runtime error (e.g. permission denied for a referenced table, or infinite recursion). Errors are not authorization decisions.",
             "Runtime error with SQLSTATE", "warning", "policy", (DOC_POLICY,), True, True,
             "Grant the policy's dependencies to the affected roles or restructure the policy to avoid recursion (for example with a SECURITY DEFINER helper that has a pinned search_path)."),
    RuleMeta("RLS-013", "Unsafe user-controlled identity context assumption",
             "A policy derives identity from a session setting that a client with SQL access can set itself. Only a proven forged-value case upgrades this beyond a static warning.",
             "Proven trust boundary weakness or explicitly static warning", "warning", "identity", (DOC_SUPABASE,), True, True,
             "Derive identity from values set by a trusted gateway after JWT verification and make sure clients cannot execute arbitrary SQL or SET the variable."),
    RuleMeta("RLS-014", "TRUNCATE / REFERENCES / TRIGGER grant outside RLS",
             "TRUNCATE, REFERENCES and TRIGGER privileges are not governed by row-level policies. This is a distinct privilege finding, not an RLS bypass.",
             "Explicit distinct privilege finding", "warning", "grants", (DOC_GRANT, DOC_RLS), True, False,
             "REVOKE TRUNCATE, REFERENCES, TRIGGER ON <table> FROM <role>."),
    RuleMeta("RLS-015", "Unexpected anonymous access",
             "The anonymous/guest identity can read or write rows the spec expects it to be denied.",
             "Actual guest identity + applicable policy/grant", "error", "isolation", (DOC_RLS,), True, True,
             "Remove anonymous grants and PUBLIC policies on private tables; expose only explicitly public rows."),
    RuleMeta("RLS-016", "Exposed sensitive column via authorized row",
             "A role that may see the row can also read a column that the spec marks as restricted.",
             "Column-grant and policy expectation", "warning", "grants", (DOC_GRANT,), True, True,
             "Use column-level GRANT SELECT (cols) or move the column to a separate, more tightly protected table/view."),
    RuleMeta("RLS-017", "Accidental all-tenant write by shared role",
             "A shared (non-tenant-bound) role or group modified rows across tenants in a controlled mutation test.",
             "Test identity + mutation proof", "error", "isolation", (DOC_POLICY,), False, True,
             "Bind write policies to the tenant predicate even for shared or support roles."),
    RuleMeta("RLS-018", "Policy semantic drift across migrations",
             "A snapshot comparison shows RLS, FORCE, policy, grant or exposure changes. A textual diff is not proof of exploitability; runtime evidence is shown when tests ran.",
             "Snapshot / test regression diff", "note", "drift", (DOC_RLS,), True, True,
             "Review the change; rerun the authorization matrix on the new schema."),
    RuleMeta("RLS-019", "Session identity/role mapping uncertainty",
             "A policy depends on session identity (settings, claims, current_user) that the run did not model, or an identity mapping could not be established. The outcome is unknown, not safe.",
             "Missing context marked INCONCLUSIVE", "note", "identity", (DOC_SUPABASE,), True, True,
             "Declare actors with explicit roles (and claims for synthetic adapters) so the context can be tested."),
    RuleMeta("RLS-020", "Uncovered tenant table / operation",
             "A protected table or SQL operation has no expectation in the spec, so its boundary is unverified. This is coverage tracking, not a vulnerability by itself.",
             "Coverage tracking, not vulnerability by itself", "note", "coverage", (DOC_RLS,), True, False,
             "Add ALLOW/DENY expectations for the missing actor/operation combinations."),
    RuleMeta("RLS-021", "Authorized access blocked",
             "An actor that the spec says must be able to perform an operation was denied (regression / availability).",
             "Runtime evidence under test roles", "warning", "regression", (DOC_POLICY,), False, True,
             "Loosen the policy minimally (or fix the grant) so the authorized operation succeeds, then re-verify the denials."),
]}


def get_rule(rule_id: str) -> RuleMeta:
    return RULES[rule_id]
