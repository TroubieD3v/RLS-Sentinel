# HTTP API

Base path `/api/v1`. Interactive OpenAPI: `/api/docs` (JSON at `/api/openapi.json`). The schema of the expected-policy
spec is served at `GET /api/v1/schema/spec`.

## Conventions

- Responses are `{"data": …, "meta": {…}}`; lists add `meta.pagination`.
- Errors use `application/problem+json` (RFC 9457 shape) with a stable `code` and `type: urn:rls-sentinel:problem:<code>`.
  Secrets are redacted from error text.
- Without an API token (single-user loopback mode), state-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`) must send
  `X-Sentinel-Client: <any value>`. A browser cannot add a custom header cross-site without a CORS preflight, which the
  API never grants, so this blocks CSRF. With a token configured, the bearer token plays that role (browsers do not
  attach it automatically).
- If a request carries an `Origin`, it must be the server's own origin or listed in `SENTINEL_ALLOWED_ORIGINS`; otherwise `403`.
- When bound to loopback, a `Host` header that is not a loopback name (or a name derived from `SENTINEL_ALLOWED_ORIGINS`) is
  answered with `421` (DNS-rebinding defence).
- With `SENTINEL_API_TOKEN` set, every route except `/health` needs `Authorization: Bearer <token>` (checked in constant time).
- Request bodies are strict: unknown fields are `422`.
- Rate limit: `SENTINEL_RATE_LIMIT_PER_MINUTE` per client address (default 240) on API routes except event streams; excess requests get `429`.
- Responses carry `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and API responses are
  `Cache-Control: no-store`. The UI is served with a strict `Content-Security-Policy` (`script-src 'self'`).

## Long-running work

`POST /test-runs`, `/scans` and `/what-if` return `202 Accepted` with the `job_id` and the run/experiment id. Follow
progress with `GET /test-runs/{id}/events` (server-sent events: `queued`, `status`, `progress`, `result`, then a terminal `completed` / `failed` / `cancelled`,
with `: heartbeat` comments in between; resume with `Last-Event-ID`) or poll `GET /jobs/{id}`. `POST /jobs/{id}/cancel` stops a job cooperatively.

```bash
curl -s -X POST http://127.0.0.1:8787/api/v1/test-runs \
  -H 'X-Sentinel-Client: cli' -H 'Content-Type: application/json' \
  -d '{"fixture":"multi-tenant-saas","variant":"vulnerable"}'
```

## Endpoints

| Area | Endpoints |
|---|---|
| Health and config | `GET /health`, `GET /settings`, `GET /stats`, `GET /rules` |
| Workspaces | `GET/POST /workspaces`, `DELETE /workspaces/{id}` |
| Connections | `GET/POST /connections`, `POST /connections/test`, `GET/DELETE /connections/{id}` — secrets are held in memory, never persisted |
| Fixtures | `GET /fixtures`, `GET /fixtures/{name}` |
| Test runs | `POST/GET /test-runs`, `GET/DELETE /test-runs/{id}`, `…/cancel`, `…/events`, `…/cases`, `…/matrix`, `…/graph`, `…/suggestions`, `…/pytest` |
| Catalog scans | `POST/GET /scans`, `GET /scans/{id}`, `…/objects`, `…/policies`, `…/graph`, `…/access-paths`, `…/snapshot`; `DELETE /snapshots/{id}` |
| Findings | `GET /findings`, `GET/PATCH /findings/{id}` (review state, owner, note) |
| Suppressions | `GET/POST /suppressions`, `DELETE /suppressions/{id}` — require reason, owner, reviewer and expiry; they hide a finding, never change results |
| What-if | `POST /what-if/lint`, `POST/GET /what-if`, `GET /what-if/{id}` |
| Diff and history | `POST /diff`, `GET /history` |
| Reports | `GET /reports/{run_id}?format=json\|md\|html\|sarif\|csv` |
| Operations | `GET /audit`, `POST /retention/purge`, `GET /jobs/{id}`, `POST /jobs/{id}/cancel`, `GET /jobs/{id}/events` |

All routes are covered by the OpenAPI document; use it as the source of truth for request and response shapes.
