"""Job worker: claim → run handler (with timeout) → complete/fail, each in its own transaction."""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel.jobs.queue import ClaimedJob, JobQueue

log = structlog.get_logger("sentinel.worker")

Handler = Callable[[dict[str, Any]], Awaitable[None]]


class Worker:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        queue: JobQueue,
        handlers: dict[str, Handler],
        *,
        name: str | None = None,
        job_timeout_s: float = 300,
        idle_sleep_s: float = 1.0,
        lease: timedelta = timedelta(minutes=10),
    ) -> None:
        self._sessions = sessions
        self._queue = queue
        self._handlers = handlers
        self.name = name or f"worker-{uuid.uuid4().hex[:8]}"
        self._timeout = job_timeout_s
        self._idle = idle_sleep_s
        self._lease = lease

    async def run_once(self) -> ClaimedJob | None:
        """Process at most one job. Returns the job processed (for tests), or None if idle."""
        if not self._handlers:
            return None
        async with self._sessions.begin() as session:
            job = await self._queue.claim(session, self.name, sorted(self._handlers))
        if job is None:
            return None
        bound = log.bind(job_id=str(job.id), kind=job.kind, attempt=job.attempts)
        try:
            await asyncio.wait_for(self._handlers[job.kind](job.payload), self._timeout)
        except Exception as exc:
            error = "timeout" if isinstance(exc, TimeoutError) else f"{type(exc).__name__}: {exc}"
            async with self._sessions.begin() as session:
                status = await self._queue.fail(session, job, error)
            bound.warning("job failed", error=error, next_status=status)
        else:
            async with self._sessions.begin() as session:
                await self._queue.complete(session, job.id)
            bound.info("job done")
        return job

    async def run_forever(self, stop: asyncio.Event) -> None:
        log.info("worker started", worker=self.name, kinds=sorted(self._handlers))
        while not stop.is_set():
            async with self._sessions.begin() as session:
                recovered = await self._queue.recover_stale(session, self._lease)
            if recovered:
                log.warning("recovered stale jobs", count=recovered)
            if await self.run_once() is None:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), self._idle)
