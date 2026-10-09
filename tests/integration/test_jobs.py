"""Postgres job queue: dedupe, SKIP LOCKED claiming, retries, leases, worker."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select

from sentinel.jobs.worker import Worker
from sentinel.persistence.models import Job

pytestmark = pytest.mark.integration


async def job_rows(container: Any) -> list[Job]:
    async with container.sessions() as session:
        return list((await session.execute(select(Job).order_by(Job.created_at))).scalars())


async def test_dedupe_key_allows_only_one_active_job(container: Any) -> None:
    async with container.sessions.begin() as s:
        first = await container.jobs.enqueue(s, "collect", {"i": 1}, dedupe_key="inc-1")
        second = await container.jobs.enqueue(s, "collect", {"i": 2}, dedupe_key="inc-1")
    assert first is not None
    assert second is None
    async with container.sessions.begin() as s:
        job = await container.jobs.claim(s, "w", ["collect"])
        assert job is not None
        await container.jobs.complete(s, job.id)
    async with container.sessions.begin() as s:  # finished jobs don't block a new one
        assert await container.jobs.enqueue(s, "collect", {}, dedupe_key="inc-1") is not None


async def test_concurrent_claims_never_share_a_job(container: Any) -> None:
    async with container.sessions.begin() as s:
        for i in range(20):
            await container.jobs.enqueue(s, "k", {"i": i})

    claimed: list[Any] = []

    async def claimer(name: str) -> None:
        while True:
            async with container.sessions.begin() as s:
                job = await container.jobs.claim(s, name, ["k"])
            if job is None:
                return
            claimed.append(job.id)

    await asyncio.gather(*(claimer(f"w{i}") for i in range(5)))
    assert len(claimed) == 20
    assert len(set(claimed)) == 20


async def test_delayed_jobs_wait_and_kinds_filter(container: Any, clock: Any) -> None:
    async with container.sessions.begin() as s:
        await container.jobs.enqueue(s, "later", {}, delay=timedelta(minutes=5))
        await container.jobs.enqueue(s, "other", {})
    async with container.sessions.begin() as s:
        assert await container.jobs.claim(s, "w", ["later"]) is None
    clock.advance(minutes=5)
    async with container.sessions.begin() as s:
        assert (await container.jobs.claim(s, "w", ["later"])) is not None


async def test_retry_with_backoff_then_failed(container: Any, clock: Any) -> None:
    async with container.sessions.begin() as s:
        await container.jobs.enqueue(s, "flaky", {}, max_attempts=3)
    statuses = []
    for _ in range(3):
        async with container.sessions.begin() as s:
            job = await container.jobs.claim(s, "w", ["flaky"])
            assert job is not None
            statuses.append(await container.jobs.fail(s, job, "boom"))
        clock.advance(minutes=10)
    assert statuses == ["pending", "pending", "failed"]
    [row] = await job_rows(container)
    assert (row.status, row.attempts, row.last_error) == ("failed", 3, "boom")


async def test_backoff_delays_retry(container: Any, clock: Any) -> None:
    async with container.sessions.begin() as s:
        await container.jobs.enqueue(s, "flaky", {})
        job = await container.jobs.claim(s, "w", ["flaky"])
        assert job is not None
        await container.jobs.fail(s, job, "boom")
    async with container.sessions.begin() as s:
        assert await container.jobs.claim(s, "w", ["flaky"]) is None  # backing off
    clock.advance(seconds=5)
    async with container.sessions.begin() as s:
        assert await container.jobs.claim(s, "w", ["flaky"]) is not None


async def test_stale_running_jobs_are_recovered(container: Any, clock: Any) -> None:
    async with container.sessions.begin() as s:
        await container.jobs.enqueue(s, "k", {})
        assert await container.jobs.claim(s, "crashed-worker", ["k"]) is not None
    clock.advance(minutes=11)
    async with container.sessions.begin() as s:
        assert await container.jobs.recover_stale(s, timedelta(minutes=10)) == 1
    async with container.sessions.begin() as s:
        assert await container.jobs.claim(s, "w2", ["k"]) is not None


async def test_worker_runs_handlers_and_records_failures(container: Any) -> None:
    seen: list[dict[str, Any]] = []

    async def ok(payload: dict[str, Any]) -> None:
        seen.append(payload)

    async def broken(_: dict[str, Any]) -> None:
        raise RuntimeError("handler exploded")

    async def slow(_: dict[str, Any]) -> None:
        await asyncio.sleep(5)

    async with container.sessions.begin() as s:
        await container.jobs.enqueue(s, "ok", {"n": 1})
        await container.jobs.enqueue(s, "broken", {}, max_attempts=1)
        await container.jobs.enqueue(s, "slow", {}, max_attempts=1)
    worker = Worker(
        container.sessions,
        container.jobs,
        {"ok": ok, "broken": broken, "slow": slow},
        job_timeout_s=0.2,
    )
    while await worker.run_once() is not None:
        pass
    by_kind = {j.kind: j for j in await job_rows(container)}
    assert seen == [{"n": 1}]
    assert by_kind["ok"].status == "done"
    assert by_kind["broken"].status == "failed"
    assert "handler exploded" in (by_kind["broken"].last_error or "")
    assert (by_kind["slow"].status, by_kind["slow"].last_error) == ("failed", "timeout")
