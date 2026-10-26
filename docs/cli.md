# Command line

```
rls-sentinel [COMMAND]
```

| Command | Purpose |
|---|---|
| `version` | tool and ruleset versions |
| `rules` | list the rule catalogue (RLS-001…021) |
| `fixtures list` | bundled synthetic fixtures |
| `spec validate FILE` / `spec schema` | validate an expected-policy spec; print its JSON Schema |
| `test` | run the authorization matrix in a **disposable** PostgreSQL |
| `scan` | read-only catalog audit of an authorised live database |
| `report RUN.json` | render JSON / Markdown / HTML / SARIF / CSV from a saved run (`--full` embeds snapshot and spec) |
| `diff BEFORE AFTER` | policy drift and test-outcome differences (`--fail-on-regression`) |
| `whatif` | replay a draft policy change in a disposable clone and diff the matrix |
| `export-tests RUN.json` | generate a pytest regression suite (`--mode spec` all must pass, `--mode pin` lock current statuses) |
| `serve` | start the API and UI (`--host`, `--port`, `--generate-token`; also `SENTINEL_HOST`, `SENTINEL_PORT`) |
| `demo up` / `demo smoke` | local demo / headless check of every bundled fixture against its documented outcome |

## `test`

```
rls-sentinel test --fixture NAME|DIR [--variant vulnerable|secure|both] [--spec FILE]
                  [--format json|sarif|html|md|csv] [-o FILE] [--fail-on critical|high|medium|low|info|none]
                  [--include-static] [--min-coverage PCT] [--backend auto|local|docker|external]
                  [--only ID ...] [--trust-fixture] [-q]
```

- `--fail-on` applies to **confirmed** violations only. `--include-static` also counts static configuration risks.
- `--min-coverage` defaults to `100`: `INCONCLUSIVE`, `ERROR`, `UNSUPPORTED` and `SKIPPED` lower verified coverage and
  therefore fail the gate with exit code `3`. Unknown is never safe.
- `--variant both` writes one file per variant (`NAME-secure.ext`, `NAME-vulnerable.ext`).
- A fixture directory outside the bundle needs `--trust-fixture` (see [authorized-testing.md](authorized-testing.md)).

## `scan`

```
SOURCE_DSN=postgresql://inspector:...@db.internal/app rls-sentinel scan --connection-env SOURCE_DSN \
    --allow-target db.internal [--spec FILE] [--schema public] [--format json|sarif|html|md] [-o FILE] \
    [--fail-on-static high] [--allow-privileged-account]
```

The connection string is read from the named environment variable only. The run is read-only (see
[threat-model.md](threat-model.md)). Only `--mode catalog` exists.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | no gating result |
| `1` | confirmed violation at or above `--fail-on`, a gating static risk (`--include-static`, `--fail-on-static`), or a regression with `--fail-on-regression` |
| `2` | usage error (bad spec, unknown fixture, disallowed target, missing environment variable) |
| `3` | the result cannot be trusted: run did not complete, fixture drift detected, or verified coverage below `--min-coverage` |

When several variants run, the worst code wins with this precedence: `2` > `3` > `1` > `0`.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `SENTINEL_HOST`, `SENTINEL_PORT` | `127.0.0.1`, `8787` | bind address of `serve` |
| `SENTINEL_API_TOKEN` | – | required for a non-loopback bind; enables token auth |
| `SENTINEL_DATA_DIR` | `~/.rls-sentinel` | SQLite metadata store and local cluster data |
| `SENTINEL_METADATA_URL` | SQLite file | SQLAlchemy URL, e.g. `postgresql+psycopg://…` |
| `SENTINEL_FIXTURE_BACKEND` | `auto` | `local` (PostgreSQL binaries), `docker`, `external` |
| `SENTINEL_FIXTURE_ADMIN_URL`, `SENTINEL_FIXTURE_DISPOSABLE` | – | operator-provisioned lab server; the second must be `true` |
| `SENTINEL_FIXTURE_IMAGE` | `postgres:17-alpine` | image for the Docker backend |
| `SENTINEL_PG_BIN` | autodetect | directory with `initdb`, `pg_ctl` |
| `SENTINEL_ALLOWED_TARGETS` | `localhost,127.0.0.0/8,::1` | hosts/CIDRs a source scan may reach |
| `SENTINEL_ALLOWED_ORIGINS` | – | extra allowed `Origin` values for the API |
| `SENTINEL_STATEMENT_TIMEOUT_MS` | `1500` | per-case statement timeout |
| `SENTINEL_MAX_PARALLELISM`, `SENTINEL_JOB_WORKERS` | `4`, `2` | concurrency limits |
| `SENTINEL_RETENTION_DAYS` | `90` | default for the retention purge |
| `SENTINEL_STORE_EXPRESSIONS` | `true` | store policy expression text in the metadata store |
| `SENTINEL_INFORMATION_URI` | – | optional project URL written to SARIF `informationUri` |
