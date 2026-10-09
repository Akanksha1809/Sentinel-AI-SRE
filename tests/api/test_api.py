"""HTTP API tests against real Postgres (ASGI in-process)."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from typing import Any, ClassVar

import httpx
import pytest
from conftest import ADMIN_TOKEN, DEPLOYER_TOKEN, WEBHOOK_TOKEN

from sentinel.domain.enums import Role
from sentinel.main import bootstrap_admin, create_app
from sentinel.security import upsert_principal

pytestmark = pytest.mark.integration

Factory = Callable[..., dict[str, Any]]
HOOK = "/api/v1/webhooks/alertmanager"
TOKENS = {
    "viewer": "snt_viewer_token_000000000000",
    "responder": "snt_responder_token_00000000",
    "approver": "snt_approver_token_000000000",
}


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


ADMIN = bearer(ADMIN_TOKEN)
WEBHOOK = bearer(WEBHOOK_TOKEN)


@pytest.fixture
async def client(container: Any) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(container, run_bootstrap=False)
    await bootstrap_admin(container)
    async with container.sessions.begin() as session:
        for role, token in TOKENS.items():
            await upsert_principal(session, container.clock, role, Role(role), token)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://sentinel") as c:
        yield c


async def open_incident(
    client: httpx.AsyncClient, am_alert: Factory, am_payload: Factory
) -> dict[str, Any]:
    r = await client.post(HOOK, json=am_payload(am_alert()), headers=WEBHOOK)
    assert r.status_code == 202, r.text
    result: dict[str, Any] = r.json()
    return result


class TestHealth:
    async def test_liveness_readiness_metrics(self, client: httpx.AsyncClient) -> None:
        assert (await client.get("/healthz")).json() == {"status": "ok"}
        ready = await client.get("/readyz")
        assert ready.status_code == 200, ready.text
        assert ready.json()["checks"]["migrations"]["ok"] is True
        metrics = (await client.get("/metrics")).text
        assert 'sentinel_build_info{version="0.1.0"} 1.0' in metrics

    async def test_correlation_id_echoed_or_generated(self, client: httpx.AsyncClient) -> None:
        r = await client.get("/healthz", headers={"X-Correlation-ID": "abc-123"})
        assert r.headers["x-correlation-id"] == "abc-123"
        r = await client.get("/healthz", headers={"X-Correlation-ID": "bad id\n!"})
        assert len(r.headers["x-correlation-id"]) == 32


class TestWebhook:
    async def test_accepts_and_creates_incident(
        self, client: httpx.AsyncClient, am_alert: Factory, am_payload: Factory
    ) -> None:
        body = await open_incident(client, am_alert, am_payload)
        assert body["received"] == 1
        assert body["new"] == 1
        assert body["incidents"][0]["short_id"] == "INC-0001"
        assert body["incidents"][0]["outcome"] == "created"

    async def test_replay_is_idempotent(
        self, client: httpx.AsyncClient, am_alert: Factory, am_payload: Factory
    ) -> None:
        await open_incident(client, am_alert, am_payload)
        body = await open_incident(client, am_alert, am_payload)
        assert (body["new"], body["updated"]) == (0, 1)
        listing = (await client.get("/api/v1/incidents", headers=ADMIN)).json()
        assert len(listing["items"]) == 1

    @pytest.mark.parametrize(
        "headers",
        [
            {},
            bearer("wrong"),
            {"Authorization": f"Basic {WEBHOOK_TOKEN}"},
            ADMIN,
        ],
    )
    async def test_rejects_bad_credentials(
        self, client: httpx.AsyncClient, headers: Any, am_alert: Factory, am_payload: Factory
    ) -> None:
        r = await client.post(HOOK, json=am_payload(am_alert()), headers=headers)
        assert r.status_code == 401
        assert r.headers["content-type"] == "application/problem+json"

    async def test_rejects_oversized_payload(self, client: httpx.AsyncClient) -> None:
        r = await client.post(
            HOOK,
            content=b"{" + b" " * 300_000 + b"}",
            headers={**WEBHOOK, "Content-Type": "application/json"},
        )
        assert r.status_code == 413

    async def test_rejects_oversized_chunked_payload(self, client: httpx.AsyncClient) -> None:
        async def chunks() -> AsyncIterator[bytes]:
            for _ in range(40):
                yield b" " * 10_000

        r = await client.post(HOOK, content=chunks(), headers=WEBHOOK)
        assert r.status_code == 413

    @pytest.mark.parametrize(
        "body",
        [
            b"not json",
            b"[]",
            b'{"version": "3", "alerts": []}',
            json.dumps(
                {"version": "4", "status": "firing", "alerts": [{"status": "firing"}]}
            ).encode(),
        ],
    )
    async def test_rejects_malformed_payloads(self, client: httpx.AsyncClient, body: bytes) -> None:
        r = await client.post(
            HOOK, content=body, headers={**WEBHOOK, "Content-Type": "application/json"}
        )
        assert r.status_code == 422
        assert r.json()["title"] == "Unprocessable Content"


class TestAuthorization:
    @pytest.mark.parametrize(
        ("role", "path", "method", "expected"),
        [
            ("viewer", "/api/v1/incidents", "GET", 200),
            ("viewer", "/api/v1/incidents/INC-0001/acknowledge", "POST", 403),
            ("responder", "/api/v1/incidents/INC-0001/acknowledge", "POST", 200),
            ("responder", "/api/v1/audit", "GET", 403),
            ("approver", "/api/v1/audit", "GET", 200),
            ("approver", "/api/v1/audit/verify", "GET", 403),
            ("admin", "/api/v1/audit/verify", "GET", 200),
        ],
    )
    async def test_role_matrix(
        self,
        client: httpx.AsyncClient,
        am_alert: Factory,
        am_payload: Factory,
        role: str,
        path: str,
        method: str,
        expected: int,
    ) -> None:
        await open_incident(client, am_alert, am_payload)
        token = ADMIN_TOKEN if role == "admin" else TOKENS[role]
        r = await client.request(
            method, path, headers=bearer(token), json={} if method == "POST" else None
        )
        assert r.status_code == expected, r.text

    @pytest.mark.parametrize("headers", [{}, bearer("snt_unknown"), bearer(WEBHOOK_TOKEN)])
    async def test_unauthenticated(self, client: httpx.AsyncClient, headers: Any) -> None:
        r = await client.get("/api/v1/incidents", headers=headers)
        assert r.status_code == 401
        assert r.headers["www-authenticate"] == "Bearer"


class TestIncidentEndpoints:
    async def test_detail_by_short_id_and_uuid(
        self, client: httpx.AsyncClient, am_alert: Factory, am_payload: Factory
    ) -> None:
        created = (await open_incident(client, am_alert, am_payload))["incidents"][0]
        by_short = (await client.get("/api/v1/incidents/INC-0001", headers=ADMIN)).json()
        by_uuid = (await client.get(f"/api/v1/incidents/{created['id']}", headers=ADMIN)).json()
        assert by_short == by_uuid
        assert by_short["alerts"][0]["alertname"] == "ShopApiHighErrorBurnRate"
        assert [e["kind"] for e in by_short["timeline"]] == ["incident.opened", "alert.attached"]
        assert "var-service=shop-api" in by_short["links"]["grafana_dashboard"]
        assert by_short["links"]["loki_explore"].startswith("http://localhost:3000/explore?")

    async def test_not_found_is_problem_json(self, client: httpx.AsyncClient) -> None:
        for ref in ("INC-9999", "nonsense", "00000000-0000-7000-8000-000000000000"):
            r = await client.get(f"/api/v1/incidents/{ref}", headers=ADMIN)
            assert r.status_code == 404
            assert r.headers["content-type"] == "application/problem+json"

    async def test_lifecycle_ack_note_resolve_close(
        self, client: httpx.AsyncClient, am_alert: Factory, am_payload: Factory
    ) -> None:
        await open_incident(client, am_alert, am_payload)
        h = bearer(TOKENS["responder"])
        base = "/api/v1/incidents/INC-0001"
        assert (await client.post(f"{base}/acknowledge", json={"note": "on it"}, headers=h)).json()[
            "status"
        ] == "acknowledged"
        assert (
            await client.post(f"{base}/notes", json={"text": "<script>x</script>"}, headers=h)
        ).status_code == 201
        resolved = (
            await client.post(f"{base}/resolve", json={"reason": "rolled back"}, headers=h)
        ).json()
        assert (resolved["status"], resolved["resolved_verified"]) == ("resolved", False)
        closed = await client.post(f"{base}/close", headers=h)
        assert closed.json()["status"] == "closed"
        again = await client.post(f"{base}/close", headers=h)
        assert again.status_code == 409
        assert again.json()["current_status"] == "closed"

    async def test_list_filters_and_pagination(
        self, client: httpx.AsyncClient, am_alert: Factory, am_payload: Factory
    ) -> None:
        for svc in ("a", "b", "c"):
            await client.post(HOOK, json=am_payload(am_alert(service=svc)), headers=WEBHOOK)
        page1 = (await client.get("/api/v1/incidents?limit=2", headers=ADMIN)).json()
        assert [i["service"] for i in page1["items"]] == ["c", "b"]
        page2 = (
            await client.get(
                f"/api/v1/incidents?limit=2&cursor={page1['next_cursor']}", headers=ADMIN
            )
        ).json()
        assert [i["service"] for i in page2["items"]] == ["a"]
        assert page2["next_cursor"] is None
        only_b = (await client.get("/api/v1/incidents?service=b", headers=ADMIN)).json()
        assert [i["service"] for i in only_b["items"]] == ["b"]
        bad = await client.get("/api/v1/incidents?status=exploded", headers=ADMIN)
        assert bad.status_code == 422


class TestDeployments:
    event: ClassVar[dict[str, str]] = {
        "service": "shop-api",
        "version": "1.1.0",
        "config_revision": "r1",
        "previous_version": "1.0.0",
        "previous_config_revision": "r1",
        "deployed_at": "2026-10-09T11:22:37+00:00",
        "deployed_by": "faults:demo-cli",
        "source": "deploy",
        "change_ref": "PR-142 price migration",
    }

    async def test_deployer_token_records_idempotently(self, client: httpx.AsyncClient) -> None:
        first = await client.post(
            "/api/v1/deployments", json=self.event, headers=bearer(DEPLOYER_TOKEN)
        )
        second = await client.post(
            "/api/v1/deployments", json=self.event, headers=bearer(DEPLOYER_TOKEN)
        )
        assert (first.status_code, second.status_code) == (201, 200)
        assert first.json()["id"] == second.json()["id"]
        listing = (await client.get("/api/v1/deployments?service=shop-api", headers=ADMIN)).json()
        assert [d["change_ref"] for d in listing] == ["PR-142 price migration"]

    @pytest.mark.parametrize("token", [TOKENS["responder"], WEBHOOK_TOKEN, "nope"])
    async def test_other_credentials_cannot_record(
        self, client: httpx.AsyncClient, token: str
    ) -> None:
        r = await client.post("/api/v1/deployments", json=self.event, headers=bearer(token))
        assert r.status_code == 401

    async def test_validation(self, client: httpx.AsyncClient) -> None:
        bad = {**self.event, "service": "../etc/passwd"}
        r = await client.post("/api/v1/deployments", json=bad, headers=bearer(DEPLOYER_TOKEN))
        assert r.status_code == 422


class TestAudit:
    async def test_actions_are_audited_with_correlation_ids_and_chain_verifies(
        self, client: httpx.AsyncClient, am_alert: Factory, am_payload: Factory
    ) -> None:
        await open_incident(client, am_alert, am_payload)
        await client.post(
            "/api/v1/incidents/INC-0001/acknowledge",
            json={},
            headers={**bearer(TOKENS["responder"]), "X-Correlation-ID": "req-42"},
        )
        events = (await client.get("/api/v1/audit", headers=ADMIN)).json()
        ack = next(e for e in events if e["action"] == "incident.acknowledged")
        assert (ack["actor"], ack["correlation_id"]) == ("user:responder", "req-42")
        verify = (await client.get("/api/v1/audit/verify", headers=ADMIN)).json()
        assert verify["ok"] is True
        assert verify["checked"] >= 3
