# Authorised testing

RLS Sentinel is a defensive tool. Use it only on databases and schemas you own or are explicitly authorised to assess.

## What touches what

| Command / UI action | Touches | Mutates? |
|---|---|---|
| `test`, Test Studio, What-if | a **disposable** server provisioned by the tool | yes, inside it, rolled back or dropped |
| `scan`, Connections → Scan | the **source** database named by your connection | **never**: read-only session, catalog queries only |
| `report`, `diff`, `export-tests` | files and the metadata store | no database access |

Behavioural tests are not available against a source database. To test your real policies behaviourally, reproduce the
schema in a fixture (below) and run it in the lab.

## Read-only audit of a live database

1. Create an unprivileged login for the audit, with `CONNECT` on the database and nothing else.
   `pg_policy`, `pg_class`, `pg_roles` and friends are readable by any role; table contents are not needed.
2. Put the connection string in an environment variable. It is never accepted on the command line:

   ```bash
   export SOURCE_DSN='postgresql://inspector:...@db.internal:5432/app?sslmode=verify-full'
   rls-sentinel scan --connection-env SOURCE_DSN --allow-target db.internal --format sarif -o scan.sarif
   ```
3. The target must match the allow-list (`SENTINEL_ALLOWED_TARGETS`, default loopback only; `--allow-target` extends it for
   one run). Cloud metadata addresses are always refused. A superuser inspector is refused unless you pass
   `--allow-privileged-account`; if you do, the report says so.
4. Review the coverage manifest printed with the result: which schemas, tables, policies and roles were seen, what was
   skipped, and the statement that no row data was collected and no runtime tests were executed.

Static findings are `CONFIGURATION_RISK`: they are leads to verify, not proof. Add an expected-policy spec with
`--spec` so the engine knows which tables are meant to be tenant-protected (RLS-001, RLS-017 and RLS-020 need it).

## Writing a fixture for your own schema

A fixture is a directory:

```
my-fixture/
  fixture.yaml                # name, roles, variants -> ordered SQL files, spec path, min_pg_major
  sql/00_roles.sql            # the roles your policies mention (NOLOGIN)
  sql/10_schema.sql
  sql/20_policies_secure.sql  # your real policies, exported with pg_dump --schema-only (no data)
  sql/30_seed.sql             # SYNTHETIC rows only: at least one per tenant per table
  specs/sentinel.yaml         # the expected policy, written independently of the SQL
```

Variant names are fixed: `secure` is the version you believe is correct, and an optional `vulnerable` is a
deliberately broken copy that proves your spec can detect the defect (a negative control).
`examples/custom-fixture` is a complete, runnable template; `fixtures/multi-tenant-saas` shows a larger one. Rules of thumb:

- Write expectations from the **requirement** ("a user can read only their tenant's invoices"), not by reading the
  policy and copying what it does. A spec derived from the code under test cannot find defects in it.
- Declare every actor with the PostgreSQL role that represents it, and its tenant.
- For each table, cover each operation for: owner-tenant actor, other-tenant actor, anonymous, and any support/service role.
- Add `expect_bypass: true` only to actors that are *meant* to be superuser/`BYPASSRLS`/owner; otherwise the case is
  `INCONCLUSIVE` by design.

Run it:

```bash
rls-sentinel spec validate my-fixture/specs/sentinel.yaml
rls-sentinel test --fixture ./my-fixture --variant secure --trust-fixture --fail-on low --min-coverage 100
```

`--trust-fixture` is required because the SQL runs as superuser on the lab server. Read it first.

## Continuous integration

`examples/github-actions/rls-sentinel.yml` runs a fixture on every pull request and uploads SARIF to code scanning.
Exit codes: `0` clean, `1` confirmed violation, `2` usage error, `3` untrustworthy result (incomplete run, fixture drift, or coverage below `--min-coverage`). See [cli.md](cli.md).
