# Threat model

Scope: the RLS Sentinel application itself. Whether *your* database is secure is what the tool measures; this page is
about how the tool avoids becoming a risk to it.

## Assets

1. The **source database** a user points the scanner at (confidentiality and integrity).
2. **Credentials** typed into the tool (DSNs, API token).
3. The **host** that runs the tool and its disposable PostgreSQL.
4. The **integrity of results**: a false "safe" is worse than no result.

## Trust boundaries

- Browser ↔ API (loopback by default; token required for any other bind).
- API ↔ source database (read-only, allow-listed).
- API ↔ disposable lab server (full control, but it holds only synthetic data).
- Spec / fixture / draft SQL supplied by a user ↔ the executor.

## Threats and the controls that exist

| # | Threat | Controls |
|---|---|---|
| T1 | Tool mutates or exfiltrates a source database | Source sessions are `default_transaction_read_only=on` in an explicit read-only transaction, with `statement_timeout`, `lock_timeout` and idle timeouts. Only the fixed set in `catalog/queries.py` can run. No row data is queried. Superuser inspectors are refused unless `--allow-privileged-account`. Behavioural tests have no code path to a source (`scan` accepts only `--mode catalog`). |
| T2 | SSRF through the connection form | `SENTINEL_ALLOWED_TARGETS` allow-list (loopback by default; empty in Compose means *none*). Every resolved address is checked, cloud metadata ranges (169.254.169.254 and similar) are always denied, multi-host strings and unix sockets are refused, and the validated address is pinned with `hostaddr` to defeat DNS rebinding between check and connect. |
| T3 | SQL injection into generated tests | Specs cannot contain raw SQL (keys such as `sql`, `query`, `raw` are rejected). The operation DSL composes identifiers with `psycopg.sql.Identifier` and binds every value. |
| T4 | Malicious fixture SQL | Bundled fixtures are trusted. A user fixture needs `--trust-fixture` and also passes an AST lint that rejects `COPY … PROGRAM`/file, `SET SESSION AUTHORIZATION`, `ALTER SYSTEM`, tablespaces, untrusted function languages, foreign data wrappers and database-level DDL. **The lint is defence in depth, not a sandbox**: the script still runs as superuser (for example, a plain `SELECT pg_read_file(...)` is not blocked), which is why it only runs on a throwaway server that holds nothing of value and why you must read a fixture before trusting it. |
| T5 | Malicious what-if draft | Parsed with pglast and checked against an allow-list: policy, RLS, grant, view, function, rename/owner, `CREATE TABLE` and index statements; `DROP` only for policies, views and functions; at most 40 statements; function languages limited to SQL and PL/pgSQL. It runs as the non-superuser owner role in a clone, and patches are *suggestions* the user applies themselves. |
| T6 | Hostile YAML | Safe loader; duplicate keys, anchors/aliases, oversized documents and deep nesting are rejected. |
| T7 | Credential leakage | DSN secrets are held in memory only. All logs go through a masking filter (DSNs, JWTs, bearer tokens, keys). API errors are redacted. Reports contain no connection strings. |
| T8 | Row-content leakage | Rows are never retained: evidence stores counts, a masked identifier (`id:<hash prefix>`) and `contents not retained`. |
| T9 | Cross-site and rebinding attacks on the local UI | When bound to loopback: `Host` validation (421 on unknown hosts, defeating DNS rebinding), `Origin` validation on state-changing requests, a required custom header (CSRF), a per-client rate limit, strict CSP and other security headers, no CORS grants. |
| T10 | Exposed service | A non-loopback bind is refused without `SENTINEL_API_TOKEN`; the token is compared in constant time and is required on every API route except `/health`. Compose publishes only to `127.0.0.1`. Plain HTTP is used: put TLS in front of it if you expose it beyond loopback. |
| T11 | Test run harms the host | Runs use a throwaway cluster or container; a fixture-level advisory lock serialises provisioning; leftover databases and roles are detected and removed; orphaned local clusters from a killed process are reaped on the next start. |
| T12 | False assurance | Coverage is computed against the *expected* assertions; `INCONCLUSIVE`, `ERROR`, `UNSUPPORTED` and `SKIPPED` never count as verified; static findings are never "confirmed"; every report states its environment and limits. |
| T13 | Tampering with the audit trail | Audit events are append-only at the ORM layer; deletion happens only through the explicit retention purge, which is itself audited. |

## Explicitly out of scope

- Compromise of the host or of the operator's account.
- A malicious operator pointing the tool at a database they are not authorised to inspect. The allow-list and the
  read-only design reduce impact; they do not replace authorisation. See [authorized-testing.md](authorized-testing.md).
- Side channels in PostgreSQL itself (timing, error-message oracles) unless a case demonstrates one.
- Application-layer authentication. Identity in tests is a PostgreSQL role or a synthetic claim.

## Residual risks

- A trusted fixture executes as superuser in the lab server and the lint cannot make that safe. Do not run fixtures you have not read.
- Static analysis of policy expressions is heuristic; see [limitations.md](limitations.md).
- The in-process job runner means a crashed server loses in-flight progress (results already stored are kept).
