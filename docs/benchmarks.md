# Benchmarks

## What is measured

`scripts/benchmark.py` runs every bundled fixture, in both variants, through the real CLI against a real PostgreSQL
server, and compares **each case's status** with the outcome documented in the fixture manifest (`expected_outcomes`).
It also records wall-clock time. `scripts/pg_matrix.py` repeats this on throwaway Docker containers for PostgreSQL 15–18.

What it does **not** measure: detection rate on real schemas, false-positive rate of static rules, or performance at
scale. The fixtures are small (16–42 cases) and known to the author. Do not read "100% agreement" as "finds 100% of defects".

## Methodology

- **Documented outcomes** were derived by hand from the policy text and PostgreSQL's documented combination rules,
  before the run, and are stored in each `fixture.yaml`.
- **Independent fixture.** `external-benchmark` is the `passwd` example from the PostgreSQL documentation
  ("Row Security Policies"); its expected behaviour comes from the documentation's prose, not from this tool. Its
  `secure` variant is the documented policy set; `vulnerable` has three hand-made mutations.
- **Negative controls.** Every `secure` variant must produce zero confirmed violations.
- **Honest history.** Two hand-derived expectations were wrong at first (a `TO PUBLIC` permissive policy also grants
  access to other tenants' rows and to non-held rows). The harness disagreed, the derivation was re-checked against the
  PostgreSQL documentation, and the manifest was corrected. This is noted in the fixture files.
- Time columns: *engine* is the test run itself (`info.duration_s`); *wall* includes process start and, for the local
  backend, provisioning a throwaway cluster. Medians of 3 repeats on the author's machine (Windows 11, PostgreSQL 18.3
  local binaries). They are indicative only.

## Results

Agreement with documented outcomes, local PostgreSQL 18.3 (raw data: [assets/benchmark.json](assets/benchmark.json)):

| Fixture | Variant | Cases | Pass | Fail | Inconclusive | Agree with documented | Engine s | Wall s |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| external-benchmark | vulnerable | 16 | 12 | 4 | 0 | 16/16 | 0.26 | 4.68 |
| external-benchmark | secure | 16 | 16 | 0 | 0 | 16/16 | 0.32 | 5.47 |
| multi-tenant-saas | vulnerable | 42 | 34 | 8 | 0 | 42/42 | 0.34 | 4.97 |
| multi-tenant-saas | secure | 42 | 42 | 0 | 0 | 42/42 | 0.35 | 5.37 |
| policy-precedence | vulnerable | 25 | 14 | 10 | 1 | 25/25 | 0.29 | 5.04 |
| policy-precedence | secure | 25 | 24 | 0 | 1 | 25/25 | 0.28 | 4.76 |
| saas-auth-context | vulnerable | 16 | 14 | 2 | 0 | 16/16 | 0.27 | 4.69 |
| saas-auth-context | secure | 16 | 16 | 0 | 0 | 16/16 | 0.28 | 4.59 |

`policy-precedence` has one `INCONCLUSIVE` case in both variants by design: a bypass role that the spec does not declare
cannot be attributed, so the tool refuses to call it either way. It lowers coverage and is shown as such.

### PostgreSQL version matrix (Docker `postgres:<N>-alpine`)

| Server | Fixture variants agreeing with documented outcomes |
|---|---|
| 15.19 | 8 / 8 (all 198 cases) |
| 16.15 | 8 / 8 (all 198 cases) |
| 17.11 | 8 / 8 (all 198 cases) |
| 18.6 | 8 / 8 (all 198 cases) |

(Engine time per fixture variant was 0.2–0.4 s on every version; wall time about 2.4–3.3 s with an already running container.)

## Reproduce

```bash
python scripts/benchmark.py --repeat 3 --md bench.md --json bench.json
python scripts/pg_matrix.py --versions 15 16 17 18          # needs Docker
rls-sentinel demo smoke                                       # headless pass/fail against documented outcomes
```
