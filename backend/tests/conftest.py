"""Shared fixtures. Integration tests need a disposable PostgreSQL (local binaries, Docker or SENTINEL_TEST_ADMIN_URL)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rls_sentinel.config import Settings, load_settings
from rls_sentinel.harness.servers import DisposableServer, ExternalServer, start_server

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def settings() -> Settings:
    s = load_settings()
    s.fixtures_dir = REPO / "fixtures"
    return s


@pytest.fixture(scope="session")
def pg_server(settings: Settings):
    """One disposable server for the whole session (fresh cluster/container, removed at the end)."""
    url = os.environ.get("SENTINEL_TEST_ADMIN_URL")
    try:
        if url:
            srv: DisposableServer = ExternalServer(url, acknowledged=True)
        else:
            srv = start_server(settings, backend=os.environ.get("SENTINEL_TEST_BACKEND"))
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"no disposable PostgreSQL available: {exc}")
    yield srv
    srv.stop()


def pytest_collection_modifyitems(config, items):
    for item in items:
        if "pg_server" in getattr(item, "fixturenames", []):
            item.add_marker(pytest.mark.pg)
