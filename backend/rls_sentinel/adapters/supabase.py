"""Supabase-style identity-context adapter (synthetic SQL path).

IMPORTANT - what this does and does not prove:
  Setting ``request.jwt.claim.sub`` (or ``request.jwt.claims``) inside a disposable database only
  exercises the *boolean logic* of policies that read those values. It does NOT prove that a real
  application authenticates the user, verifies a JWT, or protects the setting from an untrusted
  client. Results produced through this adapter are always labelled ``supabase_synthetic`` and are
  never counted as verified authentication.

The authenticated HTTP path lives in :mod:`rls_sentinel.adapters.http_probe`.
"""

from __future__ import annotations

import json

SYNTHETIC_WARNING = (
    "SYNTHETIC IDENTITY CONTEXT: claims were injected with set_config() in a disposable database. "
    "This tests policy logic only; it is not evidence that the application authenticates users or "
    "that clients cannot forge these values."
)


GUC_PREFIX = "guc:"


def claim_settings(claims: dict[str, str]) -> list[tuple[str, str]]:
    """Return the (GUC, value) pairs PostgREST-style gateways set for a request.

    Keys beginning with ``guc:`` set an arbitrary session variable directly (used to model a policy that trusts a
    free-form custom setting such as ``app.current_org``); every other key is a JWT claim.
    """
    jwt = {k: v for k, v in claims.items() if not k.startswith(GUC_PREFIX)}
    pairs = [(f"request.jwt.claim.{k}", str(v)) for k, v in sorted(jwt.items())]
    if jwt:
        pairs.append(("request.jwt.claims", json.dumps(jwt, sort_keys=True)))
    pairs += [(k[len(GUC_PREFIX):], str(v)) for k, v in sorted(claims.items()) if k.startswith(GUC_PREFIX)]
    return pairs
