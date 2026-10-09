from __future__ import annotations

import json
from collections.abc import Iterator

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from actuator.app import create_app
from actuator.fleet import FleetManager
from actuator.testing import FakeRuntime

REMEDIATE = {"Authorization": "Bearer remediation-token", "X-Actor": "sentinel-worker"}
FAULTS = {"Authorization": "Bearer fault-token"}


class ReplicaRecorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, object] | None, str | None]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.calls.append(
            (request.method, str(request.url), body, request.headers.get("X-Chaos-Token"))
        )
        return httpx.Response(202, json={"ok": True})


@pytest.fixture
def recorder() -> ReplicaRecorder:
    return ReplicaRecorder()


@pytest.fixture
def client(fleet: FleetManager, recorder: ReplicaRecorder) -> Iterator[TestClient]:
    app = create_app(
        fleet,
        actuator_token=SecretStr("remediation-token"),
        fault_token=SecretStr("fault-token"),
        chaos_token=SecretStr("chaos"),
        replica_transport=httpx.MockTransport(recorder.handler),
    )
    with TestClient(app) as c:  # lifespan reconciles + polls once
        yield c


class TestAuth:
    @pytest.mark.parametrize(
        "headers",
        [
            {},
            {"Authorization": "Bearer nope"},
            {"Authorization": "Basic remediation-token"},
            FAULTS,
        ],
    )
    def test_remediation_requires_remediation_token(
        self, client: TestClient, headers: dict[str, str]
    ) -> None:
        r = client.post("/v1/actions/restart", json={"service": "shop-api"}, headers=headers)
        assert r.status_code == 401

    def test_remediation_token_cannot_inject_faults(self, client: TestClient) -> None:
        r = client.post(
            "/v1/deploy",
            headers=REMEDIATE,
            json={"service": "shop-api", "version": "1.1.0", "config_revision": "r1"},
        )
        assert r.status_code == 401
        r = client.post("/v1/faults/shop-api/chaos/memory", headers=REMEDIATE, json={})
        assert r.status_code == 401

    def test_disabled_when_token_unset(self, fleet: FleetManager) -> None:
        app = create_app(
            fleet, actuator_token=None, fault_token=None, chaos_token=None, start_background=False
        )
        with TestClient(app) as c:
            r = c.post("/v1/actions/restart", json={"service": "shop-api"}, headers=REMEDIATE)
            assert r.status_code == 403


class TestActions:
    def test_restart_records_actor(self, client: TestClient, runtime: FakeRuntime) -> None:
        r = client.post(
            "/v1/actions/restart", headers=REMEDIATE, json={"service": "shop-api", "replica": 1}
        )
        assert r.status_code == 200, r.text
        assert r.json()["changed"] is True
        assert runtime.mutations[-1] == ("restart", "shop-api-1")

    def test_rollback_unknown_version_404(self, client: TestClient) -> None:
        r = client.post(
            "/v1/actions/rollback",
            headers=REMEDIATE,
            json={"service": "shop-api", "target_version": "0.0.1"},
        )
        assert r.status_code == 404

    @pytest.mark.parametrize(
        "body",
        [
            {"service": "shop-api", "replicas": 4},
            {"service": "shop-api", "replicas": 0},
            {"service": "shop-api", "replicas": 2, "image": "evil:latest"},
            {"service": "Shop API", "replicas": 2},
        ],
    )
    def test_scale_validation(self, client: TestClient, body: dict[str, object]) -> None:
        assert client.post("/v1/actions/scale", headers=REMEDIATE, json=body).status_code == 422

    def test_dry_run_rollback(self, client: TestClient, runtime: FakeRuntime) -> None:
        client.post(
            "/v1/deploy",
            headers=FAULTS,
            json={"service": "shop-api", "version": "1.1.0", "config_revision": "r1"},
        )
        before = list(runtime.mutations)
        r = client.post(
            "/v1/actions/rollback",
            headers=REMEDIATE,
            json={"service": "shop-api", "target_version": "1.0.0", "dry_run": True},
        )
        assert r.json()["dry_run"] is True
        assert len(r.json()["plan"]) == 2
        assert runtime.mutations == before

    def test_deployments_history_newest_first(self, client: TestClient) -> None:
        client.post(
            "/v1/deploy",
            headers=FAULTS,
            json={"service": "shop-api", "version": "1.1.0", "config_revision": "r1"},
        )
        history = client.get("/v1/deployments?service=shop-api").json()
        assert history[0]["version"] == "1.1.0"
        assert history[0]["previous_version"] == "1.0.0"
        assert history[0]["deployed_by"] == "faults:anonymous"


class TestTelemetry:
    def test_sd_targets(self, client: TestClient) -> None:
        targets = client.get("/v1/sd/targets").json()
        assert targets[0] == {
            "targets": ["shop-api-1:8000"],
            "labels": {
                "service": "shop-api",
                "replica": "1",
                "version": "1.0.0",
                "config_revision": "r1",
            },
        }

    def test_fleet_metrics(self, client: TestClient) -> None:
        body = client.get("/metrics").text
        assert 'fleet_desired_replicas{service="shop-api"} 2.0' in body
        assert (
            'fleet_container_memory_limit_bytes{replica="1",service="shop-api"} 2.68435456e+08'
            in body
        )
        assert (
            'fleet_deployment_info{config_revision="r1",service="shop-api",version="1.0.0"} 1.0'
            in body
        )
        assert "fleet_container_cpu_usage_seconds_total" in body

    def test_ready(self, client: TestClient) -> None:
        assert client.get("/readyz").status_code == 200


class TestFaultForwarding:
    def test_chaos_forwarded_to_each_running_replica_with_chaos_token(
        self, client: TestClient, recorder: ReplicaRecorder
    ) -> None:
        r = client.post(
            "/v1/faults/shop-api/chaos/memory",
            headers=FAULTS,
            json={"rate_mb_s": 2, "target_rss_mb": 200},
        )
        assert r.status_code == 200
        assert [c[1] for c in recorder.calls] == [
            "http://shop-api-1:8000/chaos/memory",
            "http://shop-api-2:8000/chaos/memory",
        ]
        assert all(c[3] == "chaos" for c in recorder.calls)

    def test_single_replica_and_unknown_mode(
        self, client: TestClient, recorder: ReplicaRecorder
    ) -> None:
        client.post("/v1/faults/shop-api/chaos/latency?replica=2", headers=FAULTS, json={})
        assert recorder.calls[-1][1] == "http://shop-api-2:8000/chaos/latency"
        r = client.post("/v1/faults/shop-api/chaos/fork-bomb", headers=FAULTS, json={})
        assert r.status_code == 422

    def test_oversized_payload_rejected(self, client: TestClient) -> None:
        r = client.post(
            "/v1/faults/shop-api/chaos/memory",
            headers=FAULTS,
            content=json.dumps({"x": "a" * 5000}),
        )
        assert r.status_code == 413
