"""HTTP hardening: auth, Host/Origin validation, CSRF-style custom header, rate limiting, security headers."""

from __future__ import annotations

import hmac
import threading
import time
from collections import defaultdict, deque

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from ..config import Settings

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
PUBLIC_PATHS = {"/api/v1/health"}
CLIENT_HEADER = "x-sentinel-client"
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


def problem(status: int, title: str, detail: str, code: str, **extra: object) -> JSONResponse:
    body = {"type": f"urn:rls-sentinel:problem:{code}", "title": title, "status": status, "detail": detail, "code": code, **extra}
    return JSONResponse(body, status_code=status, media_type="application/problem+json")


class RateLimiter:
    def __init__(self, per_minute: int):
        self.limit = per_minute
        self.hits: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            if len(self.hits) > 5000:
                for k in [k for k, v in self.hits.items() if not v][:1000]:
                    self.hits.pop(k, None)
            return True


class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings: Settings):
        super().__init__(app)
        self.s = settings
        self.limiter = RateLimiter(settings.rate_limit_per_minute)
        extra_hosts = {h.split(":")[0].lower() for h in settings.allowed_origins}
        self.allowed_hosts = LOOPBACK_HOSTS | extra_hosts | ({settings.host.lower()} if settings.host not in ("0.0.0.0", "::") else set())  # noqa: S104

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path
        raw_host = request.headers.get("host", "")
        hostname = raw_host.split("]")[0].lstrip("[") if raw_host.startswith("[") else raw_host.split(":")[0]
        if self.s.is_loopback_bind and hostname.lower() not in self.allowed_hosts:
            # DNS-rebinding defence: loopback-bound servers only answer to loopback host names
            return problem(421, "Misdirected request", f"Host '{hostname}' is not allowed.", "host_not_allowed")
        if path.startswith("/api/") and path not in PUBLIC_PATHS:
            ip = request.client.host if request.client else "?"
            if not path.endswith("/events") and not self.limiter.allow(ip):
                return problem(429, "Too many requests", "Rate limit exceeded.", "rate_limited")
            if self.s.api_token:
                auth = request.headers.get("authorization", "")
                token = auth[7:] if auth.lower().startswith("bearer ") else ""
                if not token or not hmac.compare_digest(token.encode(), self.s.api_token.encode()):
                    return problem(401, "Authentication required", "Provide the API token as 'Authorization: Bearer <token>'.", "unauthorized")
            if request.method not in SAFE_METHODS:
                if not self.s.api_token and not request.headers.get(CLIENT_HEADER):
                    return problem(403, "Missing client header", "State-changing requests need the X-Sentinel-Client header (CSRF defence).", "csrf_header_required")
                origin = request.headers.get("origin")
                if origin:
                    allowed = {f"http://{raw_host}", f"https://{raw_host}", *self.s.allowed_origins}
                    if origin not in allowed:
                        return problem(403, "Cross-origin request blocked", f"Origin '{origin}' is not allowed.", "origin_not_allowed")
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if not path.startswith("/api/"):
            response.headers.setdefault(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; "
                "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        else:
            response.headers.setdefault("Cache-Control", "no-store")
        return response
