"""Alembic environment. The connection is supplied by `Database.init()`; there is no standalone DB URL here."""
from __future__ import annotations

from alembic import context

from rls_sentinel.persistence.models import Base

target_metadata = Base.metadata


def run_migrations() -> None:
    connection = context.config.attributes.get("connection")
    if connection is None:
        raise RuntimeError("Run migrations through rls_sentinel.persistence.repo.Database.init().")
    context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


run_migrations()
