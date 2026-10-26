"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles

from .. import __version__
from ..config import Settings, load_settings
from ..errors import SentinelError
from ..persistence.repo import Database
from ..redaction import install_log_masking, redact_text
from .context import AppContext, build_context
from .routes import router
from .security import SecurityMiddleware, problem

log = logging.getLogger("rls_sentinel.api")

DESCRIPTION = """
**RLS Sentinel** discovers, tests and explains PostgreSQL Row-Level Security.

* Responses use an envelope `{ "data": ..., "meta": ... }`; errors are RFC 7807 `application/problem+json`.
* Long-running work (scans, test runs, What-if experiments) returns a **job id**; stream progress from
  `/api/v1/jobs/{id}/events` (SSE with heartbeat, resumable via `Last-Event-ID`).
* Source databases are only ever read through bounded `pg_catalog` queries. Mutating tests run exclusively in disposable databases.
"""


def create_app(settings: Settings | None = None, *, db: Database | None = None) -> FastAPI:
    settings = settings or load_settings()
    install_log_masking()
    if not settings.is_loopback_bind and not settings.api_token:
        raise RuntimeError(
            "Refusing to start: the server is bound to a non-loopback address without SENTINEL_API_TOKEN. "
            "Set a token or bind to 127.0.0.1 (unauthenticated public deployment is disabled).")
    ctx = build_context(settings, db)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        ctx.close()

    app = FastAPI(title="RLS Sentinel API", version=__version__, description=DESCRIPTION, lifespan=lifespan,
                  docs_url="/api/docs", openapi_url="/api/openapi.json", redoc_url=None)
    app.state.ctx = ctx
    app.add_middleware(SecurityMiddleware, settings=settings)
    if settings.allowed_origins:
        app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins, allow_methods=["GET", "POST", "PATCH", "DELETE"],
                           allow_headers=["Authorization", "Content-Type", "X-Sentinel-Client", "Last-Event-ID"], allow_credentials=False, max_age=600)

    @app.exception_handler(SentinelError)
    async def _sentinel(_: Request, exc: SentinelError) -> JSONResponse:
        extra = {"issues": exc.detail["issues"]} if exc.detail.get("issues") else {}
        return problem(exc.status, exc.code.replace("_", " ").title(), redact_text(exc.message), exc.code, **extra)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        issues = [{"path": ".".join(str(p) for p in e["loc"][1:]), "message": e["msg"], "level": "error"} for e in exc.errors()]
        return problem(422, "Validation error", "The request body or parameters are invalid.", "validation_error", issues=issues)

    @app.exception_handler(HTTPException)
    async def _http(_: Request, exc: HTTPException) -> JSONResponse:
        return problem(exc.status_code, "HTTP error", str(exc.detail), f"http_{exc.status_code}")

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error on %s", request.url.path)
        return problem(500, "Internal error", "An unexpected error occurred. See server logs (secrets are masked).", "internal_error")

    app.include_router(router)

    ui = settings.ui_dir
    if ui and Path(ui, "index.html").is_file():
        assets = Path(ui, "assets")
        if assets.is_dir():
            app.mount("/assets", StaticFiles(directory=assets), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        async def spa(full_path: str) -> FileResponse:
            if full_path.startswith("api/"):
                # The catch-all would otherwise mask 405 for API paths that exist under another method.
                allowed = {m for r in app.routes if isinstance(r, APIRoute) and r.path_regex.match("/" + full_path) for m in (r.methods or ())}
                if allowed:
                    raise HTTPException(405, "Method not allowed", headers={"Allow": ", ".join(sorted(allowed))})
                raise HTTPException(404, "Not found")
            candidate = (Path(ui) / full_path).resolve()
            if full_path and candidate.is_file() and Path(ui).resolve() in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(Path(ui) / "index.html")
    return app


def get_context(app: FastAPI) -> AppContext:
    return app.state.ctx
