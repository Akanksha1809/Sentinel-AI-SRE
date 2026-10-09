"""Seeded request plan and fixed-rate driver.

For a given seed the request sequence is identical on every run, so scenario
error rates are reproducible. For example, release 1.1.0 fails checkout for
products 6-10; with this mix that gives an overall error ratio of about 20%.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Iterator
from dataclasses import dataclass

import httpx
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

log = logging.getLogger("loadgen")

# (weight, method, route template)
MIX: tuple[tuple[float, str, str], ...] = (
    (0.3, "GET", "/products"),
    (0.3, "GET", "/products/{id}"),
    (0.4, "POST", "/checkout"),
)


@dataclass(frozen=True)
class PlannedRequest:
    method: str
    route: str
    path: str
    json: dict[str, int] | None


def request_plan(seed: int) -> Iterator[PlannedRequest]:
    rng = random.Random(seed)  # nosec B311 # noqa: S311 (determinism, not security)
    weights = [m[0] for m in MIX]
    while True:
        _, method, route = rng.choices(MIX, weights=weights)[0]
        pid = rng.randint(1, 10)
        if route == "/products/{id}":
            yield PlannedRequest(method, route, f"/products/{pid}", None)
        elif route == "/checkout":
            yield PlannedRequest(
                method, route, "/checkout", {"product_id": pid, "quantity": rng.randint(1, 3)}
            )
        else:
            yield PlannedRequest(method, route, route, None)


class LoadMetrics:
    def __init__(self, registry: CollectorRegistry) -> None:
        self.requests = Counter(
            "loadgen_requests_total",
            "Requests sent by outcome.",
            ["route", "outcome"],
            registry=registry,
        )
        self.dropped = Counter(
            "loadgen_dropped_total",
            "Requests skipped because max in-flight was reached.",
            registry=registry,
        )
        self.latency = Histogram(
            "loadgen_request_duration_seconds",
            "Client-observed latency.",
            ["route"],
            registry=registry,
        )
        self.rps = Gauge("loadgen_target_rps", "Configured request rate.", registry=registry)


class LoadGenerator:
    def __init__(
        self,
        client: httpx.AsyncClient,
        metrics: LoadMetrics,
        *,
        rps: float,
        seed: int,
        max_in_flight: int = 50,
    ) -> None:
        if not 0 < rps <= 200:
            raise ValueError("rps must be in (0, 200]")
        self._client = client
        self._m = metrics
        self._rps = rps
        self._plan = request_plan(seed)
        self._max_in_flight = max_in_flight
        self.in_flight = 0
        self._tasks: set[asyncio.Task[None]] = set()
        metrics.rps.set(rps)

    async def _send(self, req: PlannedRequest) -> None:
        start = time.perf_counter()
        try:
            r = await self._client.request(req.method, req.path, json=req.json)
            outcome = str(r.status_code)
        except httpx.HTTPError as exc:
            outcome = type(exc).__name__
        finally:
            self.in_flight -= 1
        self._m.requests.labels(req.route, outcome).inc()
        self._m.latency.labels(req.route).observe(time.perf_counter() - start)

    def tick(self) -> None:
        req = next(self._plan)
        if self.in_flight >= self._max_in_flight:
            self._m.dropped.inc()
            return
        self.in_flight += 1
        task = asyncio.create_task(self._send(req))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def run(self, duration_s: float | None = None) -> None:
        interval = 1.0 / self._rps
        start = time.monotonic()
        n = 0
        while duration_s is None or time.monotonic() - start < duration_s:
            self.tick()
            n += 1
            # Schedule against absolute time so the rate doesn't drift.
            await asyncio.sleep(max(0.0, start + n * interval - time.monotonic()))
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
