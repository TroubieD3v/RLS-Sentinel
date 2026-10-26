# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-26

First release.

### Added
- Behavioural RLS verification in disposable PostgreSQL (local cluster, Docker, or operator-provisioned server) with
  per-case evidence, deciding-gate detection (GRANT vs RLS), baseline controls and fixture-drift proof.
- Read-only catalog audit of authorised live databases, 21 rules (RLS-001…021) with explicit evidence classes.
- Expected-policy specification (constrained operation DSL, no raw SQL), validator and JSON Schema.
- Access graph, policy explorer, authorization matrix, snapshot/run diff and What-if Policy Lab with AST-checked drafts.
- Reports: JSON, Markdown, HTML, CSV and SARIF 2.1.0 (schema-validated); generated pytest regression suite.
- CLI (`test`, `scan`, `report`, `diff`, `whatif`, `export-tests`, `spec`, `fixtures`, `serve`, `demo`), FastAPI service with
  SSE job progress, and a React UI (dark/light, command palette, virtualised matrix, graph).
- Four synthetic fixtures with documented expected outcomes, including an independent one taken from the PostgreSQL documentation.
- Docker Compose deployment (internal disposable fixture database, hardened containers), Alembic-managed metadata store.
- Tests: 112 backend tests on real PostgreSQL, Vitest unit tests, Playwright journeys and axe-core audits.

### Known limitations
See [docs/limitations.md](docs/limitations.md).
