# Limitations

Read this before trusting a result. These are properties of the design and of this release, not future work promises.

## What a result means

1. **Scope of proof.** A `PASS` or `FAIL` describes one statement, run as one PostgreSQL role, against the *fixture copy* of
   your schema with *synthetic data*, on one server version. It does not describe production data volumes, your ORM,
   your connection pooler, `search_path` games in your application, or extensions not present in the fixture.
2. **Identity is simulated.** Actors are PostgreSQL roles (`SET ROLE`) or, in Supabase-style mode, claims injected with
   `set_config()`. Neither proves that your application authenticates users correctly or that a client cannot set the
   same setting. Those results are labelled `SYNTHETIC IDENTITY`.
3. **Coverage is relative to the spec.** `verified_coverage_pct = (PASS + FAIL) / expected assertions`. A table or
   operation with no expectation is simply not covered, and 100% coverage of a thin spec is still thin. RLS-020 reports
   uncovered tables when the spec lists them as protected.
4. **The spec is the oracle.** If the expectation is derived from the policy text, the test only confirms the policy
   does what it says. Write expectations from requirements.
5. **`INCONCLUSIVE` is a result.** It means the tool declined to guess (target row missing, bypass role not declared,
   ambiguous zero-row outcome). Treat it as work to do, not as safe.

## What it does not do

- **No behavioural testing of a live database.** Source scans are catalog-only by design.
- **No data-flow analysis of application code**, no ORM or API testing, no network scanning, no exploit generation.
- **Not every PostgreSQL feature is exercised.** Column-level policies via views, `COPY`, `TRUNCATE` semantics beyond
  grants, foreign tables, partition-specific policy inheritance, event triggers, and `LISTEN/NOTIFY` are not behaviourally
  tested by this release.
- **Policy expression analysis is heuristic.** pglast gives a real parse tree, but reasoning about arbitrary expressions
  (functions with side effects, volatile functions, subqueries over RLS tables) is incomplete. Static findings may be
  false positives and false negatives; they are labelled as inference.
- **What-if is a simulation.** It replays the matrix in a clone built from the fixture. A draft that passes there can
  still break application behaviour that has no expectation. Patches are suggestions; the tool never applies them to a source.
- **Single node.** The job runner is in-process; no clustering, HA or multi-user permission model beyond one token.
- **Local PostgreSQL 18 installations** were used for development; Docker images 15–18 were used for the version matrix.
  Other major versions, managed services (RDS, Cloud SQL, Supabase hosted) and extensions are untested.

## Benchmarks

The bundled fixtures are small and were written by the author, with expected outcomes derived by hand. Agreement with them
shows the engine is consistent with those derivations (two derivations were corrected after the harness exposed a
genuine misreading of PostgreSQL's policy-combination rules; this is recorded in the fixture manifests). It does **not**
estimate how many real-world RLS defects the tool finds or misses. See [benchmarks.md](benchmarks.md).

## Verification gaps in this release

- The automated accessibility audit (axe-core) found and fixed issues, but no manual screen-reader review was performed.
- The Docker Compose deployment was exercised with a fixture run on Docker Desktop (Windows) and on the Linux CI
  runner; macOS was not tried.
- The CI workflow (PostgreSQL 15–18, Playwright, Compose smoke test, wheel build) and the code-scanning workflow run
  green on GitHub. The Release workflow built and attested v1.0.0; its publishing step was then moved to
  `scripts/publish_release.sh`, which has not been run for a release yet. The example GitHub Action has never been executed.
