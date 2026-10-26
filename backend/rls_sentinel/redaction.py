"""Secret and sensitive-value masking.

Used for logs, stored evidence, API responses and report exports. The goal is
defence in depth: nothing that looks like a credential, JWT or connection
password should ever reach persistent storage or the browser.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit, urlunsplit

MASK = "«redacted»"

_DSN_PASSWORD = re.compile(r"(?P<scheme>[a-z][a-z0-9+.\-]*://)(?P<user>[^:/@\s]*):(?P<pw>[^@\s]*)@", re.I)
_KV_PASSWORD = re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|service[_-]?role)\b(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{0,}\b")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-~+/]{12,}=*")
_PROVIDER_KEYS = re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{30,}\b")
_LONG_LITERAL = re.compile(r"'([^']{24,})'")
_HIGH_ENTROPY = re.compile(r"^[A-Za-z0-9+/=_\-]{24,}$")
# Every pattern used by redact_text needs at least one of these substrings, so text without any of them is returned
# untouched. This keeps redaction of large snapshots cheap without weakening it.
_MAYBE_SECRET = re.compile(r"(?i)://|pass|pwd|secret|api|token|service|eyj|bearer|akia|gh[pousr]_|_(?:live|test)_")


def redact_dsn(dsn: str) -> str:
    """Return a connection string with the password replaced by a mask."""
    if not dsn:
        return dsn
    out = _DSN_PASSWORD.sub(lambda m: f"{m['scheme']}{m['user']}:{MASK}@", dsn)
    out = re.sub(r"(?i)(password\s*=\s*)('[^']*'|\S+)", rf"\1{MASK}", out)
    return out


def redact_text(text: str) -> str:
    """Mask credentials, JWTs and bearer tokens in free text."""
    if not text or not _MAYBE_SECRET.search(text):
        return text
    text = redact_dsn(text)
    text = _JWT.sub(MASK, text)
    text = _BEARER.sub(f"Bearer {MASK}", text)
    text = _PROVIDER_KEYS.sub(MASK, text)
    text = _KV_PASSWORD.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}", text)
    return text


def redact_sql_expression(expr: str | None) -> str | None:
    """Mask string literals in a policy/view expression that look like secrets.

    Short literals such as 'authenticated' or 'admin' are preserved because
    they carry the semantic meaning of the policy. Long, high-entropy literals
    are replaced.
    """
    if expr is None:
        return None

    def _sub(m: re.Match[str]) -> str:
        body = m.group(1)
        if _HIGH_ENTROPY.match(body) and not body.isalpha():
            return f"'{MASK}'"
        return m.group(0)

    out = _LONG_LITERAL.sub(_sub, expr)
    return redact_text(out)


def mask_identifier(value: Any, *, keep: int = 4) -> str:
    """Stable, short, non-reversible representation of a row identifier."""
    import hashlib

    digest = hashlib.sha256(str(value).encode()).hexdigest()
    return f"id:{digest[:keep * 2]}"


_SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "api_key", "apikey", "authorization",
    "service_role", "jwt", "dsn", "database_url", "connection_url", "admin_url",
}


def redact_obj(obj: Any, *, extra_keys: Iterable[str] = ()) -> Any:
    """Recursively redact secrets in JSON-like structures."""
    return _redact_obj(obj, _SENSITIVE_KEYS | {k.lower() for k in extra_keys})


def _redact_obj(obj: Any, keys: set[str]) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in keys and v not in (None, "", False):
                out[k] = MASK
            else:
                out[k] = _redact_obj(v, keys)
        return out
    if isinstance(obj, list | tuple):
        return [_redact_obj(v, keys) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj


def safe_url_for_display(url: str) -> str:
    """host:port/dbname without user info - for UI badges."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        netloc = f"{host}:{parts.port}" if parts.port else host
        return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    except ValueError:
        return MASK


class SecretMaskingFilter(logging.Filter):
    """Logging filter that masks secrets in messages and args."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        record.msg = redact_text(msg)
        record.args = ()
        return True


def install_log_masking() -> None:
    root = logging.getLogger()
    if not any(isinstance(f, SecretMaskingFilter) for f in root.filters):
        root.addFilter(SecretMaskingFilter())
    for handler in root.handlers:
        if not any(isinstance(f, SecretMaskingFilter) for f in handler.filters):
            handler.addFilter(SecretMaskingFilter())
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "rls_sentinel"):
        lg = logging.getLogger(name)
        if not any(isinstance(f, SecretMaskingFilter) for f in lg.filters):
            lg.addFilter(SecretMaskingFilter())
