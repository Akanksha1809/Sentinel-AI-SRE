"""Schema, roles and audit-chain guarantees against real Postgres."""

from __future__ import annotations

from typing import Any

import pytest
from conftest import ADMIN_PW, MIGRATOR_PW, PgInfo
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from sentinel.audit import verify_chain
from sentinel.persistence.db import MIGRATOR_ROLE, alembic_config, migration_head

pytestmark = pytest.mark.integration


def test_schema_is_at_head(pg: PgInfo) -> None:
    engine = create_engine(pg.app_url)
    with engine.connect() as conn:
        assert (
            conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            == migration_head()
        )
    engine.dispose()


def test_migrations_downgrade_and_upgrade_cleanly(pg: PgInfo) -> None:
    from alembic import command

    url = pg.url(MIGRATOR_ROLE, MIGRATOR_PW)
    command.downgrade(alembic_config(url), "base")
    engine = create_engine(pg.admin_url)
    with engine.connect() as conn:
        tables = conn.execute(
            text(
                "SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename <> "
                "'alembic_version'"
            )
        ).scalar()
    engine.dispose()
    assert tables == 0
    command.upgrade(alembic_config(url), "head")


@pytest.mark.parametrize(
    "statement",
    [
        "CREATE TABLE evil (id int)",
        "DROP TABLE incidents",
        "ALTER TABLE incidents ADD COLUMN x int",
        "UPDATE audit_events SET actor = 'mallory'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
    ],
)
def test_app_role_is_least_privilege(clean_db: PgInfo, statement: str) -> None:
    engine = create_engine(clean_db.app_url)
    with engine.connect() as conn, pytest.raises((ProgrammingError, DBAPIError)):
        conn.execute(text(statement))
    engine.dispose()


def test_audit_trigger_blocks_even_the_table_owner(clean_db: PgInfo) -> None:
    engine = create_engine(clean_db.url(MIGRATOR_ROLE, MIGRATOR_PW))
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO audit_events (id, at, actor, action, subject_type, subject_id, data, "
                "prev_hash, hash) VALUES (gen_random_uuid(), now(), 'a', 'b', 'c', 'd', '{}', "
                "repeat('0',64), repeat('1',64))"
            )
        )
    with engine.connect() as conn, pytest.raises(DBAPIError, match="append-only"):
        conn.execute(text("UPDATE audit_events SET actor = 'mallory'"))
    with engine.connect() as conn, pytest.raises(DBAPIError, match="append-only"):
        conn.execute(text("DELETE FROM audit_events"))
    engine.dispose()


async def test_audit_chain_verifies_and_detects_tampering(container: Any, clean_db: PgInfo) -> None:
    async with container.sessions.begin() as session:
        for i in range(5):
            await container.audit.append(
                session,
                actor="user:alice",
                action="test.event",
                subject_type="test",
                subject_id=str(i),
                data={"i": i},
            )
    async with container.sessions() as session:
        result = await verify_chain(session)
    assert (result.ok, result.checked) == (True, 5)

    # Tamper as a superuser with triggers suspended (the residual risk in the threat
    # model). The chain must expose it.
    engine = create_engine(clean_db.url("sentinel_admin", ADMIN_PW), isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        conn.execute(text("SET session_replication_role = replica"))
        conn.execute(text("UPDATE audit_events SET data = '{\"i\": 99}' WHERE seq = 3"))
    engine.dispose()
    async with container.sessions() as session:
        result = await verify_chain(session)
    assert result.ok is False
    assert result.first_bad_seq == 3
    assert result.reason == "content hash mismatch"


async def test_concurrent_audit_appends_keep_a_single_chain(container: Any) -> None:
    import asyncio

    async def writer(n: int) -> None:
        for i in range(10):
            async with container.sessions.begin() as session:
                await container.audit.append(
                    session,
                    actor=f"w{n}",
                    action="test.concurrent",
                    subject_type="test",
                    subject_id=f"{n}-{i}",
                )

    await asyncio.gather(*(writer(n) for n in range(4)))
    async with container.sessions() as session:
        result = await verify_chain(session)
    assert (result.ok, result.checked) == (True, 40)
