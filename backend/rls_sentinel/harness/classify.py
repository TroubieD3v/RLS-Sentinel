"""Pure comparison of an *observation* against an independent *expectation*.

No database access happens here, which makes the semantics unit-testable. The guiding rule is the
spec's fail-closed principle: anything that cannot be attributed with confidence is INCONCLUSIVE,
never PASS and never a confirmed violation.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..expectations.models import Actor, Expectation
from .results import ACCESS_OBSERVED, Baseline, FindingClass, RawObservation, Status

ACTOR_BYPASS = {"SUPERUSER", "BYPASSRLS", "TABLE_OWNER"}


@dataclass
class Verdict:
    status: Status
    finding_class: FindingClass
    reason: str
    violation_kind: str | None = None  # unauthorized_access | authorized_blocked | gate_mismatch | policy_error | forged_claim_accepted
    rule_hint: str | None = None
    notes: tuple[str, ...] = ()


def _v(status: Status, cls: FindingClass, reason: str, **kw) -> Verdict:
    return Verdict(status, cls, reason, **kw)


def classify(
    exp: Expectation,
    actor: Actor,
    raw: RawObservation,
    baseline: Baseline,
    *,
    control_status: str | None,
) -> Verdict:
    o = raw.observed
    notes: list[str] = []
    if o == "NOT_EXECUTED":
        return _v("SKIPPED", "INCONCLUSIVE", "Case was not executed.")
    if o in ("INFRA_ERROR", "TIMEOUT"):
        why = raw.precondition_failed or ("Statement timed out." if o == "TIMEOUT" else "Infrastructure failure.")
        return _v("ERROR", "INCONCLUSIVE",
                  f"{why} Infrastructure errors are never counted as DENY or PASS.")

    expected = exp.expected
    accessed = o in ACCESS_OBSERVED
    bypass = raw.bypass_reason if raw.bypass_reason in ACTOR_BYPASS else None
    if bypass and actor.expect_bypass:
        notes.append(f"Actor deliberately tests the {bypass} bypass path.")

    # ---------------------------------------------------------------- ERROR_EXPECTED
    if expected == "ERROR_EXPECTED":
        if accessed or o == "NO_ROWS":
            return _v("FAIL", "CONFIRMED_VIOLATION", f"Expected SQLSTATE {exp.expect_sqlstate} but the statement succeeded.",
                      violation_kind="unauthorized_access")
        if raw.sqlstate == exp.expect_sqlstate:
            return _v("PASS", "EXPECTED_DENIAL", f"Statement failed with the expected SQLSTATE {raw.sqlstate}.")
        return _v("FAIL", "CONFIRMED_VIOLATION",
                  f"Expected SQLSTATE {exp.expect_sqlstate}, observed {raw.sqlstate} ({o}).", violation_kind="gate_mismatch")

    # ------------------------------------------------- actor bypasses RLS unintentionally
    if bypass and not actor.expect_bypass:
        if expected == "ALLOW" and accessed:
            return _v("INCONCLUSIVE", "INCONCLUSIVE",
                      f"Access succeeded, but the actor role bypasses RLS ({bypass}); policies were not exercised by this case.",
                      rule_hint="RLS-004", notes=tuple(notes))
        if expected in ("DENY", "NO_ROWS") and accessed:
            return _v("FAIL", "CONFIRMED_VIOLATION",
                      f"Access succeeded because the actor role bypasses RLS ({_bypass_text(bypass)}); no policy was evaluated.",
                      violation_kind="unauthorized_access", rule_hint="RLS-004", notes=tuple(notes))

    # --------------------------------------------------------------------------- ALLOW
    if expected == "ALLOW":
        if accessed:
            return _v("PASS", "VERIFIED_ALLOW", "Authorized access succeeded as expected.", notes=tuple(notes))
        if o == "NO_ROWS":
            if baseline.target_exists is False:
                return _v("INCONCLUSIVE", "INCONCLUSIVE",
                          "Zero rows, but the target row does not exist in the fixture (baseline missing).")
            return _v("FAIL", "CONFIRMED_VIOLATION",
                      "Authorized actor received zero rows although the target exists (policy filters out the row or no policy applies).",
                      violation_kind="authorized_blocked")
        if o in ("RLS_VIOLATION", "GRANT_DENIED"):
            gate = "row-level security" if o == "RLS_VIOLATION" else "an SQL privilege (GRANT)"
            return _v("FAIL", "CONFIRMED_VIOLATION", f"Authorized access was denied by {gate}.", violation_kind="authorized_blocked")
        if o in ("POLICY_DEPENDENCY_ERROR", "POLICY_ERROR"):
            return _v("FAIL", "CONFIRMED_VIOLATION",
                      f"Policy evaluation raised SQLSTATE {raw.sqlstate}: {raw.message}", violation_kind="policy_error", rule_hint="RLS-012")
        return _v("INCONCLUSIVE", "INCONCLUSIVE",
                  f"Statement failed with SQLSTATE {raw.sqlstate} ({o}) before the authorization decision could be observed.")

    # ---------------------------------------------------------------------- NO_ROWS
    if expected == "NO_ROWS":
        if o == "NO_ROWS":
            if baseline.target_exists is False:
                return _v("INCONCLUSIVE", "INCONCLUSIVE", "Zero rows, but the target does not exist in the fixture.")
            return _v("PASS", "EXPECTED_DENIAL", "Statement succeeded and affected zero rows as expected.")
        if accessed:
            return _v("FAIL", "CONFIRMED_VIOLATION", "Rows were visible/affected but zero rows were expected.", violation_kind="unauthorized_access")
        return _v("FAIL", "CONFIRMED_VIOLATION", f"Expected a clean zero-row result, observed an error ({raw.sqlstate}).", violation_kind="gate_mismatch")

    # ------------------------------------------------------------------------- DENY
    assert expected == "DENY"
    gate_pref = exp.deny_gate
    if accessed:
        kind = "forged_claim_accepted" if exp.claims_override is not None else "unauthorized_access"
        cls: FindingClass = "CONFIGURATION_RISK" if kind == "forged_claim_accepted" else "CONFIRMED_VIOLATION"
        why = "Access succeeded although the actor must be denied."
        if exp.claims_override is not None:
            why = ("Access succeeded using forged claims. The policy trusts a session value that any SQL client can set; "
                   "this is a trust-boundary weakness only if untrusted clients can issue SQL.")
        return _v("FAIL", cls, why, violation_kind=kind, notes=tuple(notes))
    if o in ("POLICY_DEPENDENCY_ERROR", "POLICY_ERROR"):
        return _v("INCONCLUSIVE", "INCONCLUSIVE",
                  f"Denied by an error inside policy evaluation (SQLSTATE {raw.sqlstate}), not by a policy decision.",
                  violation_kind="policy_error", rule_hint="RLS-012")
    if o in ("CONSTRAINT_ERROR", "SQL_ERROR"):
        extra = ""
        if o == "CONSTRAINT_ERROR" and exp.operation in ("INSERT", "UPDATE", "UPSERT"):
            extra = " RLS WITH CHECK is evaluated before constraints, so the check did not deny this row; fix the case data so the write can reach a decision."
        return _v("INCONCLUSIVE", "INCONCLUSIVE", f"Statement failed with SQLSTATE {raw.sqlstate} ({o}); not an authorization decision.{extra}")
    if o == "NO_ROWS":
        if baseline.target_exists is False:
            return _v("INCONCLUSIVE", "INCONCLUSIVE",
                      "Zero rows, but the target row does not exist in the fixture; a filtered row is indistinguishable from an absent one.")
        if control_status not in (None, "PASS"):
            return _v("INCONCLUSIVE", "INCONCLUSIVE",
                      f"The positive control for this resource did not pass ({control_status}); a denial may be vacuous.")
        if raw.gate != "RLS":
            return _v("INCONCLUSIVE", "INCONCLUSIVE",
                      "Zero rows were returned but row-level security did not apply to this access path, so the denial cannot be attributed to RLS.")
        if gate_pref == "grant":
            return _v("FAIL", "CONFIGURATION_RISK",
                      "Expected the SQL privilege to be absent, but it is granted; rows are denied only by RLS.", violation_kind="gate_mismatch", rule_hint="RLS-010")
        return _v("PASS", "EXPECTED_DENIAL", "Zero rows: the existing target row was filtered out by row-level security.", notes=tuple(notes))
    if o == "RLS_VIOLATION":
        if gate_pref == "grant":
            return _v("FAIL", "CONFIGURATION_RISK",
                      "Expected the SQL privilege to be absent, but it is granted; the write is denied only by RLS.", violation_kind="gate_mismatch", rule_hint="RLS-010")
        return _v("PASS", "EXPECTED_DENIAL", "Denied by row-level security (new row violates a policy).")
    if o == "GRANT_DENIED":
        if gate_pref in ("grant", "any"):
            return _v("PASS", "EXPECTED_DENIAL", "Denied at the SQL privilege (GRANT) gate, as the case expects.")
        return _v("INCONCLUSIVE", "INCONCLUSIVE",
                  "Denied at the SQL GRANT gate (42501); the RLS policy was not exercised. "
                  "Set deny_gate: grant (or any) if privilege-level denial is the intended control.")
    return _v("INCONCLUSIVE", "INCONCLUSIVE", f"Unclassified observation {o}.")


def _bypass_text(b: str) -> str:
    return {"SUPERUSER": "superuser", "BYPASSRLS": "BYPASSRLS attribute", "TABLE_OWNER": "table owner without FORCE ROW LEVEL SECURITY"}.get(b, b)
