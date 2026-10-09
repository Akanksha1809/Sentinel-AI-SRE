"""Postgres-backed job queue (no Redis/Celery: one fewer service in an 8 GB budget).

- `enqueue` runs in the caller's transaction, so a job exists if and only if the
  change that caused it was committed.
- `claim` uses `FOR UPDATE SKIP LOCKED`, so concurrent workers never take the same job.
- Failures retry with exponential backoff up to `max_attempts`, then become `failed`.
- `recover_stale` returns `running` jobs whose lease expired (crashed worker) to `pending`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.ids import Clock, uuid7
from sentinel.persistence.models import Job

BACKOFF_BASE_S = 5
BACKOFF_MAX_S = 300


@dataclass(frozen=True)
class ClaimedJob:
    id: uuid.UUID
    kind: str
    payload: dict[str, Any]
    attempts: int
    max_attempts: int


class JobQueue:
    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    async def enqueue(
        self,
        session: AsyncSession,
        kind: str,
        payload: dict[str, Any],
        *,
        dedupe_key: str | None = None,
        delay: timedelta = timedelta(0),
        max_attempts: int = 3,
    ) -> uuid.UUID | None:
        """Returns the job id, or None if an active job with the same dedupe_key exists."""
        now = self._clock.now()
        stmt = insert(Job).values(
            id=uuid7(),
            kind=kind,
            payload=payload,
            dedupe_key=dedupe_key,
            max_attempts=max_attempts,
            run_after=now + delay,
            created_at=now,
        )
        if dedupe_key is not None:
            stmt = stmt.on_conflict_do_nothing(
                index_elements=["dedupe_key"],
                index_where=text("status IN ('pending', 'running')"),
            )
        return (await session.execute(stmt.returning(Job.id))).scalar_one_or_none()

    async def claim(
        self, session: AsyncSession, worker: str, kinds: list[str]
    ) -> ClaimedJob | None:
        now = self._clock.now()
        candidate = (
            select(Job.id)
            .where(Job.status == "pending", Job.run_after <= now, Job.kind.in_(kinds))
            .order_by(Job.run_after)
            .limit(1)
            .with_for_update(skip_locked=True)
            .scalar_subquery()
        )
        row = (
            await session.execute(
                update(Job)
                .where(Job.id == candidate)
                .values(
                    status="running", locked_by=worker, locked_at=now, attempts=Job.attempts + 1
                )
                .returning(Job.id, Job.kind, Job.payload, Job.attempts, Job.max_attempts)
            )
        ).one_or_none()
        return ClaimedJob(*row) if row else None

    async def complete(self, session: AsyncSession, job_id: uuid.UUID) -> None:
        await session.execute(
            update(Job)
            .where(Job.id == job_id)
            .values(status="done", finished_at=self._clock.now(), locked_by=None, last_error=None)
        )

    async def fail(self, session: AsyncSession, job: ClaimedJob, error: str) -> str:
        """Schedule a retry with backoff, or mark failed. Returns the new status."""
        now = self._clock.now()
        if job.attempts >= job.max_attempts:
            await session.execute(
                update(Job)
                .where(Job.id == job.id)
                .values(status="failed", finished_at=now, locked_by=None, last_error=error[:4000])
            )
            return "failed"
        backoff = min(BACKOFF_BASE_S * 2 ** (job.attempts - 1), BACKOFF_MAX_S)
        await session.execute(
            update(Job)
            .where(Job.id == job.id)
            .values(
                status="pending",
                run_after=now + timedelta(seconds=backoff),
                locked_by=None,
                locked_at=None,
                last_error=error[:4000],
            )
        )
        return "pending"

    async def recover_stale(self, session: AsyncSession, lease: timedelta) -> int:
        result = await session.execute(
            update(Job)
            .where(Job.status == "running", Job.locked_at < self._clock.now() - lease)
            .values(
                status="pending",
                locked_by=None,
                locked_at=None,
                last_error="lease expired (worker crashed or timed out)",
            )
        )
        return int(result.rowcount)  # type: ignore[attr-defined]

    async def counts(self, session: AsyncSession) -> dict[str, int]:
        rows = (
            await session.execute(text("SELECT status, count(*) FROM jobs GROUP BY status"))
        ).all()
        return {status: int(n) for status, n in rows}
