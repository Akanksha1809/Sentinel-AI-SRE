from __future__ import annotations

import itertools
from collections import Counter

import httpx
import pytest
from prometheus_client import CollectorRegistry

from loadgen.core import LoadGenerator, LoadMetrics, request_plan


def test_plan_is_deterministic_per_seed() -> None:
    a = list(itertools.islice(request_plan(1337), 500))
    b = list(itertools.islice(request_plan(1337), 500))
    c = list(itertools.islice(request_plan(7), 500))
    assert a == b
    assert a != c


def test_mix_proportions_and_defect_exposure() -> None:
    plan = list(itertools.islice(request_plan(1337), 5000))
    routes = Counter(r.route for r in plan)
    assert 0.37 < routes["/checkout"] / 5000 < 0.43
    # Share of all requests that would hit release 1.1.0's nulled prices (products 6-10).
    broken = sum(1 for r in plan if r.route == "/checkout" and r.json and r.json["product_id"] > 5)
    assert 0.17 < broken / 5000 < 0.23


async def test_driver_counts_outcomes_and_bounds_in_flight() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500 if request.url.path == "/checkout" else 200)

    registry = CollectorRegistry()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://t"
    ) as client:
        gen = LoadGenerator(client, LoadMetrics(registry), rps=200, seed=1, max_in_flight=5)
        await gen.run(duration_s=0.25)
    sent = sum(
        registry.get_sample_value("loadgen_requests_total", {"route": r, "outcome": o}) or 0
        for r in ("/products", "/products/{id}", "/checkout")
        for o in ("200", "500")
    )
    assert sent > 20
    assert gen.in_flight == 0


def test_rps_bounds() -> None:
    with pytest.raises(ValueError, match="rps"):
        LoadGenerator(httpx.AsyncClient(), LoadMetrics(CollectorRegistry()), rps=0, seed=1)
