"""Engine / session factory and database role bootstrap."""

from __future__ import annotations

import re
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"
APP_ROLE = "sentinel_app"
MIGRATOR_ROLE = "sentinel_migrator"


def make_engine(url: str, pool_size: int = 5) -> AsyncEngine:
    return create_async_engine(
        url,
        pool_size=pool_size,
        max_overflow=pool_size,
        pool_pre_ping=True,
        pool_timeout=10,
        connect_args={"connect_timeout": 5, "options": "-c statement_timeout=15000"},
    )


def make_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


def _literal(password: str) -> str:
    # Passwords are generated hex (scripts/gen-secrets.sh); reject anything else so a
    # value can never break out of the SQL string literal.
    if not re.fullmatch(r"[A-Za-z0-9_\-]{16,128}", password):
        raise ValueError("database role passwords must be 16-128 chars of [A-Za-z0-9_-]")
    return "'" + password + "'"


def bootstrap_roles(
    conn: Connection, database: str, migrator_password: str, app_password: str
) -> None:
    """Create/refresh the two least-privilege roles. Run as the DB superuser (idempotent).

    - sentinel_migrator owns the schema and runs Alembic (DDL).
    - sentinel_app is used by the API and worker: DML only (no DDL), and by default no
      UPDATE/DELETE on audit_events (granted per table in migrations).
    """
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", database):
        raise ValueError("invalid database name")
    for role, pw in ((MIGRATOR_ROLE, migrator_password), (APP_ROLE, app_password)):
        exists = conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role})
        verb = "ALTER" if exists.scalar() else "CREATE"
        conn.execute(
            text(
                f"{verb} ROLE {role} LOGIN PASSWORD {_literal(pw)} "
                "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION"
            )
        )
    conn.execute(text(f"GRANT CONNECT, CREATE ON DATABASE {database} TO {MIGRATOR_ROLE}"))
    conn.execute(text(f"GRANT CONNECT ON DATABASE {database} TO {APP_ROLE}"))
    conn.execute(text("REVOKE CREATE ON SCHEMA public FROM PUBLIC"))
    conn.execute(text(f"ALTER SCHEMA public OWNER TO {MIGRATOR_ROLE}"))
    conn.execute(text(f"GRANT USAGE ON SCHEMA public TO {APP_ROLE}"))


def alembic_config(url: str | None = None) -> Config:
    """Alembic config pointing at the migrations shipped inside the package."""
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    if url:
        cfg.attributes["url"] = url
    return cfg


def migration_head() -> str | None:
    return ScriptDirectory.from_config(alembic_config()).get_current_head()


def upgrade(url: str) -> None:
    command.upgrade(alembic_config(url), "head")
