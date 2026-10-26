# PostgreSQL RLS semantics the tool relies on

Expectations in the bundled fixtures were derived from these rules (and from the PostgreSQL documentation, section
"Row Security Policies"), then checked against a real server. Where the first derivation was wrong the harness caught
it; those corrections are recorded in the fixture manifests.

## Gates, in order

A statement by role *R* on table *T* passes two independent gates:

1. **SQL privilege gate** (`GRANT`). Missing privilege → SQLSTATE `42501` *before* any row policy is consulted.
   Column privileges apply to the columns named in `SELECT` / `INSERT` / `UPDATE` lists. The tool records
   `has_table_privilege` / `has_column_privilege` and reports `gate = GRANT` so a denial is not mistaken for an RLS success.
2. **Row-security gate.** Only if the privilege gate passed and RLS applies to *R* on *T*.

A test that is stopped at the grant gate proves nothing about the policies. The overview counts these separately
(`grant_gate_only`), and the matrix shows `DENY · GRANT` versus `DENY · RLS`.

## When RLS applies

| Situation | RLS applied? |
|---|---|
| `ENABLE ROW LEVEL SECURITY` not set | no |
| superuser, or a role with `BYPASSRLS` (attribute is **not inherited** through membership) | no |
| table owner | no, unless `FORCE ROW LEVEL SECURITY` |
| `row_security = off` and a policy would apply | error instead of silent bypass |
| RLS enabled, no policy for the command | **default deny** |

## Combining policies

- Permissive policies for the same command and role are OR-ed.
- Restrictive policies are AND-ed with the permissive result.
- A table with only restrictive policies grants nothing.
- `CREATE POLICY` defaults to `PERMISSIVE`; writing "restrictive intent" without the keyword is a common defect
  (fixture `policy-precedence`).
- `TO PUBLIC` (the default) applies to every role, including ones created later.

## Per command

| Command | `USING` | `WITH CHECK` |
|---|---|---|
| `SELECT` | rows visible | – |
| `INSERT` | – | new row must satisfy |
| `UPDATE` | rows that may be targeted (also gate `SELECT`-style lookups) | new row must satisfy; if absent, `USING` is reused |
| `DELETE` | rows that may be targeted | – |
| `ALL` | both | both |

Consequences the tool tests explicitly:

- `UPDATE` and `DELETE` need a matching `SELECT` policy for any `WHERE`/`RETURNING` that reads columns.
- Moving a row to another tenant is an `UPDATE` whose **new** row must pass `WITH CHECK`
  (`bob-cannot-move-own-project-to-alpha`).
- `WITH CHECK` failures raise SQLSTATE `42501` with *new row violates row-level security policy*; they are evaluated
  before constraint checks, which matters for `UPSERT`.
- A denied `SELECT`/`UPDATE`/`DELETE` is usually **zero rows**, not an error. The harness therefore compares row counts
  and uses a *baseline* (does the target exist? does an authorised actor see it?) so "no rows" is not mistaken for "no access".

## Views and functions

- A view runs with the privileges and RLS context of its **owner** unless `security_invoker = true` (PostgreSQL 15+).
  An owner-privileged view over an RLS table can expose other tenants' rows (`bob-cannot-read-alpha-invoice-via-owner-view`).
- `SECURITY DEFINER` functions run as their owner; without a pinned `search_path` they are also a hijack surface.
  The function case executes `EXECUTE` as the actor and checks the result against the expectation.

## Identity

Tests set identity with `SET LOCAL ROLE` from a non-superuser, `NOINHERIT` harness login that is a member of every actor
role. For Supabase-style fixtures, claims are injected with `set_config()` inside the disposable database. That
exercises policy *logic*; it never proves that an application authenticates users or that a client cannot set
the same setting. Such results carry the label `SYNTHETIC IDENTITY`.
