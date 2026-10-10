"""The three demo scenarios, run against the real Compose stack end to end:
fault -> real Prometheus alert -> real incident -> real (mock) investigation ->
approve -> real actuator remediation -> real verified recovery.

Needs `SENTINEL_EXECUTION_MODE=live` (`make e2e-up`) — see `tests/e2e/conftest.py`.
Each scenario's trigger resets the fleet and closes any still-open incident for the
service first (see `sentinel.demo.scenarios._reset_baseline`), so each is safe to
run alone. Run as a suite, order matters, and C is the fragile one: a crash-loop
(POOL_SIZE=0) never completes a request, so it produces no "5xx response" metric
signal at all and very few log lines before each restart — a genuinely weak
correlation signal on its own merits (measured live: ~0.4 vs. the mock's 0.6
threshold), not merely one that loses to louder competing evidence. Evidence
correlation looks back a full hour (`CHANGE_LOOKBACK` in `evidence/collector.py` —
correct for real incidents, where a deployment an hour ago can still be the cause),
so *any* error/warning volume left over from a scenario run shortly before C's own
(scenario B's error logs, or even scenario A's memory-pressure metric shape) can
tip its investigation toward the wrong runbook. B and A are both robust regardless
of what ran before them (confirmed live). So C runs first here, while the window is
quietest; A and B follow in either order.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sentinel.demo.client import SentinelDemoClient
from sentinel.demo.scenarios import SCENARIOS

pytestmark = pytest.mark.e2e

# Generous but bounded: evidence/investigation are near-instant (mock provider),
# execution is a real container replace/restart (tens of seconds), verification
# windows are up to settle_s + window_s per runbooks/*.yaml (worst case ~2 minutes).
_TIMEOUT_S = 180.0


async def _run_scenario(demo: SentinelDemoClient, scenario_id: str) -> None:
    scenario = SCENARIOS[scenario_id]
    started_at = datetime.now(UTC)
    await scenario.trigger(demo)

    incident = await demo.wait_for_incident("shop-api", opened_after=started_at, timeout_s=90)
    ref = incident["short_id"]
    assert incident["severity"] in ("warning", "critical")

    investigation = await demo.wait_for_investigation(ref, timeout_s=90)
    assert investigation["status"] == "succeeded"
    assert investigation["is_mock"] is True
    assert investigation["hypotheses"], "expected at least one hypothesis"

    action = await demo.wait_for_proposed_action(ref, timeout_s=30)
    assert action["runbook_id"] == scenario.expected_runbook
    assert action["status"] == "pending_approval"

    await demo.approve(action["id"], f"e2e test: scenario {scenario_id}")

    resolved = await demo.wait_for_resolution(ref, timeout_s=_TIMEOUT_S)
    assert resolved["status"] == "resolved"
    assert resolved["resolved_verified"] is True

    detail = await demo.incident_detail(ref)
    kinds = [e["kind"] for e in detail["timeline"]]
    assert "investigation.completed" in kinds
    assert "action.approved" in kinds
    assert "action.verified" in kinds


async def test_1_scenario_c_bad_config_rolls_back(demo: SentinelDemoClient) -> None:
    await _run_scenario(demo, "c")


async def test_2_scenario_a_memory_leak_restarts_the_service(demo: SentinelDemoClient) -> None:
    await _run_scenario(demo, "a")


async def test_3_scenario_b_bad_release_rolls_back(demo: SentinelDemoClient) -> None:
    await _run_scenario(demo, "b")
