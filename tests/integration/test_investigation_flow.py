"""Alert → evidence → investigation (mock / failing provider) → API, on real Postgres."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from datetime import datetime
from typing import Any

import httpx
import pytest
from conftest import ADMIN_TOKEN, WEBHOOK_TOKEN

from sentinel.evidence.collector import EvidenceCollector
from sentinel.evidence.model import LogLine, Point, Series
from sentinel.evidence.service import JOB_KIND as EVIDENCE_JOB
from sentinel.evidence.service import EvidenceService
from sentinel.investigation.providers import MockProvider, ProviderError
from sentinel.investigation.schemas import InvestigationRequest
from sentinel.investigation.service import JOB_KIND as INVESTIGATION_JOB
from sentinel.investigation.service import InvestigationService
from sentinel.jobs.worker import Worker
from sentinel.main import bootstrap_admin, create_app

pytestmark = pytest.mark.integration
Factory = Callable[..., dict[str, Any]]
ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
HOOK = {"Authorization": f"Bearer {WEBHOOK_TOKEN}"}


class ScenarioB:
    """Telemetry for a broken release: errors jump, all on 1.1.0."""

    async def query_range(
        self, query: str, start: datetime, end: datetime, step_s: float
    ) -> list[Series]:
        if "error_ratio" in query:
            pts = tuple(
                Point(start.timestamp() + 15 * i, 0.0 if i < 118 else 0.2) for i in range(130)
            )
            return [Series({"service": "shop-api"}, pts)]
        return []

    async def query_instant(self, query: str, at: datetime) -> list[Series]:
        return [Series({"version": "1.1.0"}, (Point(at.timestamp(), 120.0),))]

    async def query_logs(
        self, query: str, start: datetime, end: datetime, limit: int
    ) -> list[LogLine]:
        line = (
            '{"msg": "unhandled error", "exception": "TypeError: unsupported operand '
            "type(s) for *: 'NoneType' and 'int'\"}"
        )
        return [LogLine(end.timestamp(), {"version": "1.1.0", "config_revision": "r1"}, line)]

    async def query_log_metrics(
        self, query: str, start: datetime, end: datetime, step_s: float
    ) -> list[Series]:
        return [
            Series({"version": "1.1.0", "config_revision": "r1"}, (Point(end.timestamp(), 50.0),))
        ]


class BrokenLLM:
    name, model, is_mock = "ollama", "qwen2.5-coder:3b", False

    async def investigate(self, request: InvestigationRequest) -> dict[str, Any]:
        raise ProviderError("ollama unreachable: ConnectError")


class HallucinatingLLM:
    name, model, is_mock = "ollama", "qwen2.5-coder:3b", False

    async def investigate(self, request: InvestigationRequest) -> dict[str, Any]:
        return {
            "summary": "Definitely the database.",
            "suspected_root_cause": {
                "statement": "Database failover",
                "confidence": 0.99,
                "cited_evidence": ["metric.db_failover"],
            },
            "recommended_actions": [
                {"runbook_id": "failover-db", "parameters": {"cluster": "prod"}}
            ],
        }


@pytest.fixture
async def client(container: Any) -> AsyncIterator[httpx.AsyncClient]:
    await bootstrap_admin(container)
    transport = httpx.ASGITransport(app=create_app(container, run_bootstrap=False))
    async with httpx.AsyncClient(transport=transport, base_url="http://sentinel") as c:
        yield c


def worker(container: Any, llm: Any = None) -> Worker:
    t = ScenarioB()
    evidence = EvidenceService(
        container.sessions,
        container.clock,
        container.incidents,
        EvidenceCollector(t, t),
        container.metrics,
        jobs=container.jobs,
        auto_investigate_with="ollama" if llm else "mock",
    )
    providers: dict[str, Any] = {"mock": MockProvider()}
    if llm:
        providers["ollama"] = llm
    inv = InvestigationService(
        container.sessions,
        container.clock,
        container.incidents,
        container.audit,
        container.catalog,
        providers,
        container.metrics,
    )
    return Worker(
        container.sessions,
        container.jobs,
        {EVIDENCE_JOB: evidence.handle_job, INVESTIGATION_JOB: inv.handle_job},
    )


async def drain(container: Any, clock: Any, w: Worker) -> None:
    clock.advance(seconds=30)
    while await w.run_once() is not None:
        pass


async def deploy_and_alert(
    client: httpx.AsyncClient, am_alert: Factory, am_payload: Factory, container: Any
) -> None:
    deployer = {"Authorization": f"Bearer {container.settings.deployer_token.get_secret_value()}"}
    start = container.clock.now()
    await client.post(
        "/api/v1/deployments",
        headers=deployer,
        json={
            "service": "shop-api",
            "version": "1.1.0",
            "previous_version": "1.0.0",
            "config_revision": "r1",
            "previous_config_revision": "r1",
            "deployed_at": start.isoformat(),
            "deployed_by": "ci",
            "source": "deploy",
            "change_ref": "PR-142",
        },
    )
    await client.post(
        "/api/v1/webhooks/alertmanager", headers=HOOK, json=am_payload(am_alert(starts_at=start))
    )


async def test_full_automatic_chain_with_mock(
    client: httpx.AsyncClient, container: Any, clock: Any, am_alert: Factory, am_payload: Factory
) -> None:
    await deploy_and_alert(client, am_alert, am_payload, container)
    await drain(container, clock, worker(container))

    [inv] = (await client.get("/api/v1/incidents/INC-0001/investigations", headers=ADMIN)).json()
    assert inv["status"] == "succeeded"
    assert inv["is_mock"] is True
    assert "MOCK" in inv["label"]
    assert inv["summary"].startswith("[MOCK]")
    root = inv["hypotheses"][0]
    assert (root["kind"], root["generated"], root["uncited"]) == (
        "suspected_root_cause",
        True,
        False,
    )
    assert "derived.change_correlation" in root["cited_evidence"]
    [action] = inv["recommended_actions"]
    assert action["runbook_id"] == "rollback-deployment"
    assert action["parameters"] == {"service": "shop-api", "target_version": "1.0.0"}
    assert action["requires_approval"] is True

    incident = (await client.get("/api/v1/incidents/INC-0001", headers=ADMIN)).json()
    assert incident["status"] == "investigating"
    kinds = [e["kind"] for e in incident["timeline"]]
    assert kinds.index("evidence.collected") < kinds.index("investigation.completed")
    assert any(e["actor"] == "ai:MOCK" for e in incident["timeline"])


async def test_llm_failure_is_recorded_and_never_replaced_by_mock(
    client: httpx.AsyncClient,
    container: Any,
    clock: Any,
    am_alert: Factory,
    am_payload: Factory,
) -> None:
    await deploy_and_alert(client, am_alert, am_payload, container)
    await drain(container, clock, worker(container, BrokenLLM()))
    [inv] = (await client.get("/api/v1/incidents/INC-0001/investigations", headers=ADMIN)).json()
    assert inv["status"] == "failed"
    assert inv["provider"] == "ollama"
    assert "unreachable" in inv["error"]
    assert inv["hypotheses"] == []
    incident = (await client.get("/api/v1/incidents/INC-0001", headers=ADMIN)).json()
    assert incident["status"] == "open"  # no investigation result → no status change
    assert incident["timeline"][-1]["kind"] == "investigation.failed"


async def test_hallucinated_output_is_contained(
    client: httpx.AsyncClient, container: Any, clock: Any, am_alert: Factory, am_payload: Factory
) -> None:
    await deploy_and_alert(client, am_alert, am_payload, container)
    await drain(container, clock, worker(container, HallucinatingLLM()))
    [inv] = (await client.get("/api/v1/incidents/INC-0001/investigations", headers=ADMIN)).json()
    assert inv["status"] == "succeeded"
    root = inv["hypotheses"][0]
    assert root["uncited"] is True
    assert root["confidence"] <= 0.3
    assert inv["recommended_actions"] == []
    assert inv["rejected_actions"][0]["reason"] == "not in the runbook catalogue"
    assert inv["dropped_citations"] == ["suspected_root_cause: metric.db_failover"]


async def test_manual_request_rules(
    client: httpx.AsyncClient, container: Any, clock: Any, am_alert: Factory, am_payload: Factory
) -> None:
    await client.post("/api/v1/webhooks/alertmanager", headers=HOOK, json=am_payload(am_alert()))
    r = await client.post("/api/v1/incidents/INC-0001/investigations", headers=ADMIN, json={})
    assert r.status_code == 409  # no evidence yet
    assert "no evidence" in r.json()["detail"]
    r = await client.post(
        "/api/v1/incidents/INC-0001/investigations", headers=ADMIN, json={"provider": "ollama"}
    )
    assert r.status_code == 409  # disabled in settings
    await drain(container, clock, worker(container))
    first = await client.post(
        "/api/v1/incidents/INC-0001/investigations", headers=ADMIN, json={"provider": "mock"}
    )
    second = await client.post(
        "/api/v1/incidents/INC-0001/investigations", headers=ADMIN, json={"provider": "mock"}
    )
    assert (first.json()["queued"], second.json()["queued"]) == (True, False)
    bad = await client.post(
        "/api/v1/incidents/INC-0001/investigations", headers=ADMIN, json={"provider": "gpt-cloud"}
    )
    assert bad.status_code == 422


async def test_runbook_catalogue_endpoint(client: httpx.AsyncClient) -> None:
    books = (await client.get("/api/v1/runbooks", headers=ADMIN)).json()
    assert {b["id"] for b in books} == {"restart-service", "rollback-deployment", "scale-service"}
    assert all(len(b["sha256"]) == 64 for b in books)
    assert (await client.get("/api/v1/runbooks/nope", headers=ADMIN)).status_code == 404


async def test_new_kind_of_alert_refocuses_and_reinvestigates(
    client: httpx.AsyncClient,
    container: Any,
    clock: Any,
    am_alert: Factory,
    am_payload: Factory,
) -> None:
    from sqlalchemy import select

    from sentinel.persistence.models import Job

    await client.post(
        "/api/v1/webhooks/alertmanager",
        headers=HOOK,
        json=am_payload(am_alert("ShopApiHighLatency", severity="warning")),
    )
    w = worker(container)
    await drain(container, clock, w)  # evidence + first investigation
    # Same alertname again (new startsAt): no refocus, no re-investigation.
    await client.post(
        "/api/v1/webhooks/alertmanager",
        headers=HOOK,
        json=am_payload(am_alert("ShopApiHighLatency", severity="warning", starts_at=clock.now())),
    )
    async with container.sessions() as s:
        triggers = [j.payload.get("trigger") for j in (await s.execute(select(Job))).scalars()]
    assert "alert.attached:ShopApiHighLatency" in triggers
    await drain(container, clock, w)
    # A different problem joins the incident: refocus + re-investigate.
    await client.post(
        "/api/v1/webhooks/alertmanager",
        headers=HOOK,
        json=am_payload(am_alert("ShopApiCrashLooping", starts_at=clock.now())),
    )
    await drain(container, clock, w)
    invs = (await client.get("/api/v1/incidents/INC-0001/investigations", headers=ADMIN)).json()
    assert len(invs) == 2
    evidence = (await client.get("/api/v1/incidents/INC-0001/evidence", headers=ADMIN)).json()
    assert evidence["trigger"] == "alert.new:ShopApiCrashLooping"
    onset = next(i for i in evidence["items"] if i["ref"] == "derived.onset")
    assert onset["data"]["focus_alertnames"] == ["ShopApiCrashLooping"]
