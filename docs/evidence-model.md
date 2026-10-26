# Evidence model

The product's central rule: **a result is only as strong as its evidence, and the UI says which kind it is.**

## Case status

| Status | Meaning | Counts as verified? |
|---|---|---|
| `PASS` | the observation matches the independent expectation, in a valid context | yes |
| `FAIL` | the observation contradicts the expectation, and a baseline shows the test was meaningful | yes |
| `INCONCLUSIVE` | the result cannot be attributed with confidence (missing target row, bypass role not declared, ambiguous zero-row result, claim not applied…) | **no** |
| `ERROR` | the harness failed | no |
| `UNSUPPORTED` | the construct is outside what the harness can test | no |
| `SKIPPED` | not executed (cancelled, budget) | no |

`verified_coverage_pct = (PASS + FAIL) / expected assertions`. Everything else lowers it. `--min-coverage` makes the CLI
exit non-zero when coverage is below a threshold, so "unknown" can never silently become "safe".

## Finding evidence classes

| Class | Produced by | Wording |
|---|---|---|
| `CONFIRMED_VIOLATION` | a runtime `FAIL` against an independent expectation | "Confirmed in a disposable database" |
| `CONFIGURATION_RISK` | static catalog analysis | "inference", never "confirmed"; may be a false positive |
| `INCONCLUSIVE` | unknown context | explains what is missing |
| `UNSUPPORTED` | out of scope construct | says so |

Each finding carries: rule id, severity with rationale, confidence, provenance tags
(`CATALOG_FACT`, `STATIC_INFERENCE`, `RUNTIME_OBSERVATION`, `USER_EXPECTATION`), the case ids it rests on, a stable
fingerprint (so review decisions and suppressions survive re-runs), limitations, reproduction steps and remediation text.

## What a case records

`session_user` and `current_user`; role flags (superuser, `BYPASSRLS`, effective owner); `rls_enabled` / `rls_forced` /
whether RLS applies; `row_security` setting; privilege result and gate; applicable policies; SQLSTATE and message
(redacted); observed outcome (`ROW_RETURNED`, `ROWS_AFFECTED`, `ROW_INSERTED`, `NO_ROWS`, `RLS_VIOLATION`, `GRANT_DENIED`, `POLICY_DEPENDENCY_ERROR`, `CONSTRAINT_ERROR`, `TIMEOUT`, …);
a parameterised statement with masked parameters; row **count** and masked identifiers. Row contents are not stored.

## Isolation proof

Each run stores a digest of fixture data and policies before and after execution, whether the harness login was
superuser/`BYPASSRLS` (it must not be), and whether any source database was touched (it never is). These appear in the
report under *Isolation*.

## Reproducibility

Reports include the tool and ruleset versions, PostgreSQL version, schema hash, spec checksum and fixture fingerprint.
Two runs with equal hashes against the same server version are expected to agree. `scripts/benchmark.py` runs each fixture several times and reports median timings, but it only compares the last repeat with the documented expectations; it is not a statistical determinism test.
