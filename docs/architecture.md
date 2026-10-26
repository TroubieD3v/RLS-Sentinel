# Architecture

RLS Sentinel is one Python package (`rls_sentinel`) with three front doors: a Typer CLI, a FastAPI service and a
React single-page UI served by that service. All three call the same engine.

```
                         ┌───────────────────────────── rls_sentinel ──────────────────────────────┐
  CLI (Typer) ───────────►                                                                          │
  HTTP API (FastAPI) ────►  service / jobs ─► harness ──► disposable PostgreSQL   (behavioural tests)│
  React UI (static) ─────►                 └► catalog ──► source PostgreSQL       (read-only)        │
                         │  rules · graph · diff · whatif · reporting · persistence                  │
                         └───────────────────────────────────────────────────────────────────────────┘
```

## Two kinds of database, never mixed

| | Disposable lab server | Source database |
|---|---|---|
| Purpose | run behavioural tests, what-if replays | static catalog audit |
| Who creates it | the tool (local cluster, Docker, or an operator-provisioned server acknowledged as disposable) | you; you must be authorised to inspect it |
| Connection | superuser **owned by the lab only** for provisioning; tests run as a non-superuser harness login | an unprivileged inspector login you choose |
| What runs | generated, parameterised statements inside transactions that are always rolled back | a closed set of bounded `SELECT`s on `pg_catalog` |
| Row data | synthetic seed only | never read |

`ExternalServer` refuses to start unless `SENTINEL_FIXTURE_DISPOSABLE=true`, verifies it is a superuser-owned server
with no unexpected databases, and refuses to share a host:port with the metadata store.

## Packages

| Package | Responsibility |
|---|---|
| `catalog/` | read-only session (`connection.py`), the closed query set (`queries.py`), snapshot builder (`introspect.py`), expression analysis with pglast (`exprs.py`), migration line provenance (`migrations.py`) |
| `expectations/` | the expected-policy spec: strict Pydantic models, safe YAML loader (duplicate keys, aliases, size and depth limits), validation against a snapshot |
| `harness/` | disposable servers (`servers.py`), fixture loading and provisioning (`fixtures.py`), the operation DSL (`ops.py`), raw observation (`executor.py`), pure classification (`classify.py`), orchestration (`runner.py`) |
| `rules/` | RLS-001…021 registry and engine; a finding's class is decided by evidence, not by rule |
| `graph/` | role/membership graph and the typed access graph with provenance and caps |
| `diff/` | semantic snapshot diff and run diff |
| `whatif/` | draft linting, sandbox replay, remediation suggestions |
| `reporting/` | report model, JSON/MD/HTML/CSV/SARIF exporters, matrix, generated pytest suite |
| `persistence/` | SQLAlchemy 2 metadata store (SQLite locally, PostgreSQL in Compose) with Alembic migrations |
| `api/` | routes, security middleware, job manager with SSE |
| `cli/` | commands |

## One behavioural case

```
BEGIN;
SET LOCAL ROLE <actor role>;          -- authorised by real membership of the non-inheriting harness login
<probes: has_table_privilege, pg_has_role, applicable policies, role flags>
SAVEPOINT s; <generated statement>; ROLLBACK TO s;
ROLLBACK;
```

`classify()` is a pure function of *(observation, independent expectation, baseline)*. Anything it cannot attribute
with confidence becomes `INCONCLUSIVE`. A data and policy digest taken before and after the run proves the fixture did
not drift (`isolation.no_fixture_drift`).

## Jobs and streaming

Long operations are in-process jobs on a small thread pool. Progress is published as server-sent events with a
heartbeat; clients can resume with `Last-Event-ID`. Jobs left running by a crashed process are marked failed on start.
There is deliberately no external queue: the product is a single-node tool.

## Storage

The metadata store keeps workspaces, snapshots, runs, cases, findings, review decisions, suppressions, what-if
experiments and an append-only audit log. It never stores connection secrets (they live in a per-process vault) and
never stores row contents. The schema is versioned with Alembic (`persistence/migrations`); `Database.init()` upgrades
to head and stamps stores created before versioning.

## Frontend

React 19 + Vite + Tailwind 4 with CSS-variable design tokens, TanStack Query, `@xyflow/react` for the graph,
Radix primitives for dialogs and tooltips, and a virtualised ARIA grid for the matrix. The built bundle is copied into
the wheel and served with a strict `Content-Security-Policy`. See [design-system.md](design-system.md).
