#!/usr/bin/env python3
"""Write a .env with fresh random secrets for docker compose. Refuses to overwrite an existing file."""
from __future__ import annotations

import secrets
import sys
from pathlib import Path

target = Path(__file__).resolve().parent.parent / ".env"
if target.exists():
    sys.exit(f"{target} already exists; delete it first if you really want new secrets.")
target.write_text(
    f"SENTINEL_API_TOKEN={secrets.token_urlsafe(32)}\n"
    f"METADATA_DB_PASSWORD={secrets.token_urlsafe(24)}\n"
    f"FIXTURE_DB_PASSWORD={secrets.token_urlsafe(24)}\n"
    "SENTINEL_ALLOWED_TARGETS=\n",
    encoding="utf-8",
)
try:
    target.chmod(0o600)
except OSError:
    pass
print(f"wrote {target} (not tracked by git)")
