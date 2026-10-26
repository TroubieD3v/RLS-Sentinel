"""The Alembic history is the source of truth for the metadata store; it must match the ORM models exactly."""
from __future__ import annotations

from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

from rls_sentinel.persistence.models import Base
from rls_sentinel.persistence.repo import Database


def _drift(db: Database) -> list:
    with db.engine.connect() as conn:
        return compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata)


def test_fresh_store_is_created_by_migrations_and_matches_models(tmp_path):
    db = Database(f"sqlite:///{(tmp_path / 'a.db').as_posix()}")
    db.init()
    assert "alembic_version" in inspect(db.engine).get_table_names()
    assert _drift(db) == []
    db.init()  # idempotent
    db.dispose()


def test_store_created_before_versioning_is_stamped_not_recreated(tmp_path):
    url = f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}"
    legacy = create_engine(url)
    Base.metadata.create_all(legacy)
    with legacy.begin() as c:
        c.execute(text("INSERT INTO workspace (id, name, description, created_at) VALUES ('w1', 'keep-me', '', CURRENT_TIMESTAMP)"))
    legacy.dispose()
    db = Database(url)
    db.init()
    with db.engine.connect() as c:
        assert c.execute(text("SELECT name FROM workspace WHERE id='w1'")).scalar() == "keep-me"
        assert c.execute(text("SELECT version_num FROM alembic_version")).scalar() == "0001"
    db.dispose()
