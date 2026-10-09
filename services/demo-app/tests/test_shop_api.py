from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from shop_api.__main__ import main
from shop_api.app import create_app
from shop_api.chaos import MB, ChaosEngine, ChaosLimitError, LatencyFault, MemoryFault
from shop_api.config import Settings

TOKEN = "test-chaos-token"
AUTH = {"X-Chaos-Token": TOKEN}


def make_client(**overrides: object) -> TestClient:
    settings = Settings(chaos_token=TOKEN, **overrides)  # type: ignore[arg-type]
    return TestClient(create_app(settings), raise_server_exceptions=False)


@pytest.fixture
def client() -> Iterator[TestClient]:
    with make_client() as c:
        yield c


@pytest.fixture
def broken_client() -> Iterator[TestClient]:
    with make_client(app_version="1.1.0", release_defect="checkout_null_price") as c:
        yield c


class TestBusinessEndpoints:
    def test_healthy_release_checkouts_all_succeed(self, client: TestClient) -> None:
        codes = [
            client.post("/checkout", json={"product_id": pid}).status_code for pid in range(1, 11)
        ]
        assert codes == [200] * 10

    def test_broken_release_fails_deterministically_for_nulled_products(
        self, broken_client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.ERROR, logger="shop_api")
        codes = {
            pid: broken_client.post("/checkout", json={"product_id": pid}).status_code
            for pid in range(1, 11)
        }
        assert codes == {
            1: 200,
            2: 200,
            3: 200,
            4: 200,
            5: 200,
            6: 500,
            7: 500,
            8: 500,
            9: 500,
            10: 500,
        }
        errors = [r for r in caplog.records if r.msg == "unhandled error"]
        assert len(errors) == 5
        assert errors[0].exc_info is not None
        assert errors[0].exc_info[0] is TypeError

    def test_unknown_product_is_404(self, client: TestClient) -> None:
        assert client.get("/products/999").status_code == 404

    def test_checkout_validates_quantity(self, client: TestClient) -> None:
        assert client.post("/checkout", json={"product_id": 1, "quantity": 0}).status_code == 422


class TestObservability:
    def test_metrics_use_route_templates_and_status_codes(self, broken_client: TestClient) -> None:
        broken_client.get("/products/3")
        broken_client.post("/checkout", json={"product_id": 6})
        body = broken_client.get("/metrics").text
        assert (
            'http_requests_total{code="200",method="GET",route="/products/{product_id}"} 1.0'
            in body
        )
        assert 'http_requests_total{code="500",method="POST",route="/checkout"} 1.0' in body
        assert 'shop_checkouts_total{outcome="error"} 1.0' in body
        assert (
            'shop_app_info{app_config_revision="r1",app_version="1.1.0",'
            'release_defect="checkout_null_price"} 1.0' in body
        )
        # ops endpoints are not counted as traffic
        assert 'route="/metrics"' not in body

    def test_request_id_echoed_and_sanitised(self, client: TestClient) -> None:
        assert (
            client.get("/products", headers={"X-Request-ID": "abc123"}).headers["X-Request-ID"]
            == "abc123"
        )
        generated = client.get("/products", headers={"X-Request-ID": "x" * 500}).headers[
            "X-Request-ID"
        ]
        assert len(generated) == 32

    def test_health_and_readiness(self, client: TestClient) -> None:
        assert client.get("/healthz").json() == {"status": "ok"}
        assert client.get("/readyz").status_code == 200


class TestChaosAuthAndBounds:
    def test_chaos_disabled_without_configured_token(self) -> None:
        with TestClient(create_app(Settings())) as c:
            assert c.get("/chaos", headers=AUTH).status_code == 403

    def test_chaos_rejects_wrong_or_missing_token(self, client: TestClient) -> None:
        assert client.get("/chaos").status_code == 401
        assert client.get("/chaos", headers={"X-Chaos-Token": "nope"}).status_code == 401
        assert client.get("/chaos", headers=AUTH).status_code == 200

    def test_memory_target_above_cap_rejected(self, client: TestClient) -> None:
        r = client.post("/chaos/memory", headers=AUTH, json={"target_rss_mb": 4096})
        assert r.status_code == 422

    def test_duration_above_cap_rejected(self, client: TestClient) -> None:
        r = client.post("/chaos/latency", headers=AUTH, json={"delay_ms": 10, "duration_s": 3600})
        assert r.status_code == 422

    def test_out_of_schema_values_rejected(self, client: TestClient) -> None:
        assert client.post("/chaos/cpu", headers=AUTH, json={"duration_s": 121}).status_code == 422
        assert (
            client.post("/chaos/latency", headers=AUTH, json={"delay_ms": 5000}).status_code == 422
        )
        assert (
            client.post("/chaos/memory", headers=AUTH, json={"rate_mb_s": 100}).status_code == 422
        )

    def test_latency_fault_applies_and_clears(self, client: TestClient) -> None:
        assert (
            client.post(
                "/chaos/latency", headers=AUTH, json={"delay_ms": 50, "duration_s": 60}
            ).status_code
            == 202
        )
        assert client.get("/chaos", headers=AUTH).json()["latency"]["active"] is True
        client.delete("/chaos", headers=AUTH)
        assert client.get("/chaos", headers=AUTH).json()["latency"]["active"] is False


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def start_memory_manually(engine: ChaosEngine, fault: MemoryFault) -> None:
    """Start the memory fault, then cancel the background loop so ticks are driven by the test."""

    async def run() -> None:
        await engine.start_memory(fault)
        task = engine._memory_task
        assert task is not None
        task.cancel()

    asyncio.run(run())


class TestChaosEngine:
    def test_memory_growth_stops_at_target_rss(self) -> None:
        baseline = 10 * MB
        holder: list[ChaosEngine] = []
        engine = ChaosEngine(
            64,
            600,
            clock=FakeClock(),
            rss_reader=lambda: baseline + holder[0].memory_allocated_bytes(),
        )
        holder.append(engine)
        start_memory_manually(engine, MemoryFault(rate_mb_s=8, target_rss_mb=20, duration_s=60))
        for _ in range(50):
            engine.memory_step()
        assert baseline + engine.memory_allocated_bytes() == 20 * MB

    def test_memory_released_on_expiry(self) -> None:
        clock = FakeClock()
        engine = ChaosEngine(64, 600, clock=clock, rss_reader=lambda: 0)
        start_memory_manually(engine, MemoryFault(rate_mb_s=4, target_rss_mb=32, duration_s=10))
        engine.memory_step()
        assert engine.memory_allocated_bytes() == 1 * MB
        clock.now += 11
        assert engine.memory_step() is False
        assert engine.memory_allocated_bytes() == 0

    def test_memory_cap_enforced_by_engine(self) -> None:
        engine = ChaosEngine(64, 600)
        with pytest.raises(ChaosLimitError):
            start_memory_manually(engine, MemoryFault(target_rss_mb=65))

    def test_latency_expires(self) -> None:
        clock = FakeClock()
        engine = ChaosEngine(64, 600, clock=clock)
        engine.start_latency(LatencyFault(delay_ms=200, duration_s=5))
        assert engine.injected_latency_s() == pytest.approx(0.2)
        clock.now += 5
        assert engine.injected_latency_s() == 0.0


class TestFailFastConfig:
    def test_invalid_pool_size_exits_nonzero_with_clear_log(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("POOL_SIZE", "0")
        monkeypatch.setenv("CONFIG_REVISION", "r2")
        assert main() == 1
        line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert line["level"] == "critical"
        assert "config validation failed" in line["msg"]
        assert "POOL_SIZE" in line["msg"]
        assert line["config_revision"] == "r2"
