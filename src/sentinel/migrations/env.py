"""Alembic environment. Migrations run synchronously as the `sentinel_migrator` role."""

from __future__ import annotations

import os

from alembic import context
from sqlalchemy import create_engine, pool

from sentinel.persistence.models import Base

config = context.config
target_metadata = Base.metadata


def _url() -> str:
    url = config.attributes.get("url") or os.environ.get("SENTINEL_MIGRATION_URL")
    if not url:
        raise RuntimeError("set SENTINEL_MIGRATION_URL (or pass attributes['url'])")
    return str(url)


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
