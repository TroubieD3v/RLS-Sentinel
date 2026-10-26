"""Domain errors. Each carries a stable machine code used in problem+json responses."""

from __future__ import annotations


class SentinelError(Exception):
    code = "sentinel_error"
    status = 400

    def __init__(self, message: str, *, detail: dict | None = None):
        super().__init__(message)
        self.message = message
        self.detail = detail or {}


class SpecError(SentinelError):
    """The expectation specification is invalid."""

    code = "invalid_spec"
    status = 422

    def __init__(self, message: str, *, issues: list[dict] | None = None):
        super().__init__(message, detail={"issues": issues or []})
        self.issues = issues or []


class ConnectionRefusedByPolicy(SentinelError):
    """The target is not allowed by the network allowlist or safety policy."""

    code = "target_not_allowed"
    status = 403


class ConnectionFailed(SentinelError):
    code = "connection_failed"
    status = 502


class UnsafeOperation(SentinelError):
    """An operation that would mutate a non-disposable database was requested."""

    code = "unsafe_operation"
    status = 409


class NotFound(SentinelError):
    code = "not_found"
    status = 404


class Conflict(SentinelError):
    code = "conflict"
    status = 409


class ProvisioningError(SentinelError):
    code = "provisioning_failed"
    status = 503


class UnsupportedFeature(SentinelError):
    code = "unsupported"
    status = 422
