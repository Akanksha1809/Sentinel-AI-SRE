"""The three demo scenarios, matching `deploy/actuator/releases.yaml`'s catalogue
comments exactly (scenario B is release `1.1.0`, scenario C is config `r2`) and the
runbook catalogue's `applies_to_alerts` (see `runbooks/*.yaml`).

Each scenario's `reset` restores the known-good baseline (`1.0.0`/`r1`) first — the
actuator's deploy is idempotent, so this is always safe, and it's what makes `run`
repeatable rather than only working once per stack lifetime.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from sentinel.demo.client import SentinelDemoClient

SERVICE = "shop-api"
_BASELINE_VERSION = "1.0.0"
_BASELINE_CONFIG = "r1"


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    description: str
    expected_alert: str
    expected_runbook: str
    trigger: Callable[[SentinelDemoClient], Awaitable[None]]


async def _reset_baseline(client: SentinelDemoClient) -> None:
    await client.reset_active_incidents(SERVICE)
    await client.deploy(_BASELINE_VERSION, _BASELINE_CONFIG, "sentinel-demo:reset")
    await client.clear_chaos()


async def _trigger_a(client: SentinelDemoClient) -> None:
    await _reset_baseline(client)
    await client.inject_memory_chaos()


async def _trigger_b(client: SentinelDemoClient) -> None:
    await _reset_baseline(client)
    await client.deploy("1.1.0", _BASELINE_CONFIG, "sentinel-demo:scenario-b")


async def _trigger_c(client: SentinelDemoClient) -> None:
    await _reset_baseline(client)
    await client.deploy(_BASELINE_VERSION, "r2", "sentinel-demo:scenario-c")


SCENARIOS: dict[str, Scenario] = {
    "a": Scenario(
        id="a",
        title="Memory leak",
        description=(
            "Chaos-inject steady memory growth on shop-api (no deployment involved). "
            "Prometheus fires ShopApiMemoryPressure; the mock investigator recognises "
            "an uncorrelated memory climb and recommends a rolling restart."
        ),
        expected_alert="ShopApiMemoryPressure",
        expected_runbook="restart-service",
        trigger=_trigger_a,
    ),
    "b": Scenario(
        id="b",
        title="Bad release",
        description=(
            "Deploy shop-api 1.1.0, which ships a bad price migration (nulls prices "
            "for products 6-10, so checkout raises TypeError). Prometheus fires "
            "ShopApiHighErrorBurnRate; the mock investigator correlates the error "
            "spike with the deployment and recommends rolling back to 1.0.0."
        ),
        expected_alert="ShopApiHighErrorBurnRate",
        expected_runbook="rollback-deployment",
        trigger=_trigger_b,
    ),
    "c": Scenario(
        id="c",
        title="Bad config",
        description=(
            "Deploy shop-api config revision r2 (POOL_SIZE=0, fails startup "
            "validation). Prometheus fires ShopApiCrashLooping/ShopApiDown; the mock "
            "investigator recommends rolling back to config r1."
        ),
        expected_alert="ShopApiCrashLooping",
        expected_runbook="rollback-deployment",
        trigger=_trigger_c,
    ),
}
