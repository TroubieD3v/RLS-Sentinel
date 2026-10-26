# Development

## Prerequisites

- Python 3.12+, Node 22+, and either PostgreSQL 15+ server binaries (`initdb`, `pg_ctl`; set `SENTINEL_PG_BIN` if not on the
  default path) or Docker for the disposable lab.

## Setup

```bash
cd backend
python -m venv .venv
.venv/bin/pip install -e ".[dev]"          # Windows: .venv\Scripts\pip
cd ../frontend && npm ci
```

## Checks

```bash
# backend
cd backend
ruff check rls_sentinel tests
mypy rls_sentinel
pytest                                      # real PostgreSQL; ~1 min

# frontend
cd frontend
npm run lint && npm run typecheck && npm test
npx playwright install chromium             # once
SENTINEL_BIN=../backend/.venv/bin/rls-sentinel npx playwright test    # journey, mobile and axe audits
```

`pytest` uses a session-wide disposable server. To use a server you provisioned, set
`SENTINEL_TEST_ADMIN_URL=postgresql://postgres:…@127.0.0.1:5432/postgres` (it must be disposable) and, optionally,
`SENTINEL_TEST_BACKEND=local|docker`.

## Running from source

```bash
cd frontend && npm run build               # the API serves frontend/dist when no bundled UI is present
cd ../backend && rls-sentinel serve        # http://localhost:8787
cd ../frontend && npm run dev              # Vite dev server on :5173 proxying /api to :8787
```

## Release build

```bash
python scripts/build_release.py            # UI build + bundle + wheel/sdist + SHA256SUMS in dist/
```

## Documentation screenshots

```bash
cd frontend
SCREENSHOTS=1 SENTINEL_BIN=… npx playwright test e2e/screenshots.spec.ts --project=desktop
```

They are taken from a real run of the bundled fixture; do not replace them with mock-ups.

## Conventions

- Anything that is not proven must say so. New rules need a minimum-evidence statement in `rules/registry.py`.
- `classify()` stays pure. Fail closed: when attribution is uncertain return `INCONCLUSIVE`.
- Never execute SQL text taken from a spec; extend the operation DSL instead.
- Never store row contents or connection secrets, and run new log lines through the masking filter.
- Fixtures contain synthetic data only; expectations are derived from requirements, not from tool output.
- Schema changes to the metadata store need an Alembic revision (`persistence/migrations/versions`) and the drift test
  `tests/unit/test_migrations.py` must pass.
