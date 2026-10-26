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

## Scale

`scripts/scale_benchmark.py` generates a synthetic multi-tenant schema of a chosen size and times every phase of a real
run separately against a real PostgreSQL server. Each table has 10 policies (tenant-scoped SELECT/INSERT/UPDATE/DELETE, one
restrictive policy, five unrelated audit policies) and 4 behavioural expectations. Every 25th table has a planted
`USING (true)` SELECT leak and every 40th a `WITH CHECK (true)` INSERT leak, so each run also checks that exactly the
planted violations are found.

Local PostgreSQL 18.3, Windows 11, 32 logical CPUs, harness parallelism 4; median of 3 runs
(raw data: [assets/scale-benchmark.json](assets/scale-benchmark.json)):

| Tables | Policies | Cases | Planted / found | Provision | Catalog snapshot | Behavioural tests | Rule engine | Graph | Reports (model + JSON/HTML/SARIF) | Store in metadata DB | Total |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 100 | 1 000 | 400 | 7 / 7 | 0.95 s | 0.14 s | 1.02 s | 0.02 s | 0.04 s | 0.23 s | 0.53 s | 5.8 s |
| 300 | 3 000 | 1 200 | 20 / 20 | 1.90 s | 0.29 s | 2.36 s | 0.08 s | 0.20 s | 0.70 s | 1.23 s | 9.8 s |
| 1 000 | 10 000 | 4 000 | 65 / 65 | 5.54 s | 0.74 s | 8.75 s | 0.31 s | 1.03 s | 2.47 s | 4.01 s | 26.8 s |

Totals include about 2.7 s to start a throwaway cluster, which is paid once per run. Behavioural tests cost about 2.2 ms
per case and scale linearly. At 1 000 tables the run produced 6 155 findings (mostly per-table static notes), a graph of
21 177 nodes and 56 390 edges (the UI shows a capped, focused subgraph), an 8 MB HTML report and a 7.3 MB SARIF file.
Peak Python allocations during that run, measured with `tracemalloc`, were 392 MiB.

What the first measurement found, and what changed (the "before" column analysed only 5 000 policies, so the real
gain is larger than shown):

| Problem at 1 000 tables | Before | After |
|---|---:|---:|
| Catalog listing stopped at 5 000 policies without failing the run (it was recorded only in the coverage manifest) | 5 000 of 10 000 policies analysed | all 10 000; limits raised, and hitting one now adds a coverage note to the report |
| Rule engine looked tables and grants up by scanning lists (quadratic) | 4.18 s | 0.31 s |
| Migration line numbers counted newlines from the start of the file for every statement | 2.99 s | 0.50 s |
| Secret redaction ran every regular expression on every stored string | 5.17 s to store | 4.01 s |

Limits that remain: a YAML spec is capped at 256 KiB and 20 000 nodes, and `execution.max_statements` at 5 000, as a
defence against hostile input. That is enough for about 1 000 tables at 4 expectations each; larger suites should be
split by schema. Numbers above are from one machine and are indicative only.

```bash
python scripts/scale_benchmark.py --tables 100 300 1000 --repeat 3 [--memory]
```
