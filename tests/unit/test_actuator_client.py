"""HttpActuatorClient against mocked HTTP (respx): error classification and dry-run forcing."""

from __future__ import annotations

import httpx
import pytest
import respx

from sentinel.remediation.actuator_client import (
    ActuatorError,
    ActuatorUnavailableError,
    DryRunActuatorClient,
    HttpActuatorClient,
)

BASE = "http://actuator.test"


def result(
    action: str = "restart",
    changed: bool = True,
    plan: list[str] | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    return {
        "action": action,
        "service": "shop-api",
        "dry_run": dry_run,
        "changed": changed,
        "plan": plan or [],
        "before": {},
        "after": {},
    }


@pytest.fixture
def client() -> HttpActuatorClient:
    return HttpActuatorClient(BASE, "tok")


class TestSuccess:
    @respx.mock
    async def test_restart_sends_bearer_and_actor_header(self, client: HttpActuatorClient) -> None:
        route = respx.post(f"{BASE}/v1/actions/restart").mock(
            return_value=httpx.Response(200, json=result("restart"))
        )
        r = await client.restart("shop-api", 1, actor="sentinel:worker", dry_run=False)
        assert r.changed is True
        assert r.action == "restart"
        req = route.calls.last.request
        assert req.headers["authorization"] == "Bearer tok"
        assert req.headers["x-actor"] == "sentinel:worker"
        import json

        assert json.loads(req.content) == {"service": "shop-api", "dry_run": False, "replica": 1}

    @respx.mock
    async def test_rollback_omits_config_revision_when_none(
        self, client: HttpActuatorClient
    ) -> None:
        route = respx.post(f"{BASE}/v1/actions/rollback").mock(
            return_value=httpx.Response(200, json=result("rollback"))
        )
        await client.rollback("shop-api", "1.0.0", None, actor="a", dry_run=True)
        import json

        body = json.loads(route.calls.last.request.content)
        assert "target_config_revision" not in body
        assert body == {"service": "shop-api", "target_version": "1.0.0", "dry_run": True}

    @respx.mock
    async def test_scale(self, client: HttpActuatorClient) -> None:
        respx.post(f"{BASE}/v1/actions/scale").mock(
            return_value=httpx.Response(200, json=result("scale", changed=False))
        )
        r = await client.scale("shop-api", 2, actor="a", dry_run=False)
        assert r.changed is False


class TestErrorClassification:
    @pytest.mark.parametrize(
        ("status", "body"),
        [
            (404, {"error": "unknown_target"}),
            (422, {"error": "out_of_bounds"}),
            (403, {"error": "not_managed"}),
            (409, {"error": "precondition_failed"}),
            (401, {"detail": "invalid credentials"}),
        ],
    )
    @respx.mock
    async def test_terminal_errors_never_retryable(
        self, client: HttpActuatorClient, status: int, body: dict[str, str]
    ) -> None:
        respx.post(f"{BASE}/v1/actions/restart").mock(
            return_value=httpx.Response(status, json=body)
        )
        with pytest.raises(ActuatorError):
            await client.restart("shop-api", None, actor="a", dry_run=False)

    @respx.mock
    async def test_503_is_unavailable_not_terminal(self, client: HttpActuatorClient) -> None:
        respx.post(f"{BASE}/v1/actions/restart").mock(return_value=httpx.Response(503))
        with pytest.raises(ActuatorUnavailableError):
            await client.restart("shop-api", None, actor="a", dry_run=False)

    @respx.mock
    async def test_500_is_unavailable(self, client: HttpActuatorClient) -> None:
        respx.post(f"{BASE}/v1/actions/restart").mock(return_value=httpx.Response(500))
        with pytest.raises(ActuatorUnavailableError):
            await client.restart("shop-api", None, actor="a", dry_run=False)

    @respx.mock
    async def test_connection_error_is_unavailable(self, client: HttpActuatorClient) -> None:
        respx.post(f"{BASE}/v1/actions/restart").mock(side_effect=httpx.ConnectError("refused"))
        with pytest.raises(ActuatorUnavailableError):
            await client.restart("shop-api", None, actor="a", dry_run=False)

    @respx.mock
    async def test_timeout_is_unavailable(self, client: HttpActuatorClient) -> None:
        respx.post(f"{BASE}/v1/actions/restart").mock(side_effect=httpx.TimeoutException("slow"))
        with pytest.raises(ActuatorUnavailableError):
            await client.restart("shop-api", None, actor="a", dry_run=False)


class TestDryRunWrapper:
    @respx.mock
    async def test_forces_dry_run_true_even_when_caller_asks_for_live(
        self, client: HttpActuatorClient
    ) -> None:
        route = respx.post(f"{BASE}/v1/actions/rollback").mock(
            return_value=httpx.Response(200, json=result("rollback", dry_run=True))
        )
        wrapped = DryRunActuatorClient(client)
        await wrapped.rollback("shop-api", "1.0.0", "r1", actor="a", dry_run=False)
        import json

        assert json.loads(route.calls.last.request.content)["dry_run"] is True
