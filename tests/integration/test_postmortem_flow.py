"""Alert → evidence → investigation → postmortem generate/edit/finalize, on real Postgres.

Mirrors test_investigation_flow.py's scenario setup so the generated postmortem has a
real MOCK hypothesis and a real proposed action to render, not just empty sections.
"""

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
from sentinel.investigation.providers import MockProvider
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


@pytest.fixture
async def client(container: Any) -> AsyncIterator[httpx.AsyncClient]:
    await bootstrap_admin(container)
    transport = httpx.ASGITransport(app=create_app(container, run_bootstrap=False))
    async with httpx.AsyncClient(transport=transport, base_url="http://sentinel") as c:
        yield c


def worker(container: Any) -> Worker:
    t = ScenarioB()
    evidence = EvidenceService(
        container.sessions,
        container.clock,
        container.incidents,
        EvidenceCollector(t, t),
        container.metrics,
        jobs=container.jobs,
        auto_investigate_with="mock",
    )
    inv = InvestigationService(
        container.sessions,
        container.clock,
        container.incidents,
        container.audit,
        container.catalog,
        {"mock": MockProvider()},
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


async def deploy_alert_and_investigate(
    client: httpx.AsyncClient, container: Any, clock: Any, am_alert: Factory, am_payload: Factory
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
    await drain(container, clock, worker(container))


class TestGenerate:
    async def test_generate_before_any_incident_data_is_404(
        self, client: httpx.AsyncClient
    ) -> None:
        r = await client.post("/api/v1/incidents/INC-0001/postmortem", headers=ADMIN)
        assert r.status_code == 404

    async def test_get_before_generate_is_404(
        self,
        client: httpx.AsyncClient,
        container: Any,
        clock: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        await deploy_alert_and_investigate(client, container, clock, am_alert, am_payload)
        r = await client.get("/api/v1/incidents/INC-0001/postmortem", headers=ADMIN)
        assert r.status_code == 404

    async def test_generate_renders_mock_hypothesis_and_evidence(
        self,
        client: httpx.AsyncClient,
        container: Any,
        clock: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        await deploy_alert_and_investigate(client, container, clock, am_alert, am_payload)
        proposed = await client.post(
            "/api/v1/incidents/INC-0001/actions",
            headers=ADMIN,
            json={
                "runbook_id": "rollback-deployment",
                "parameters": {"service": "shop-api", "target_version": "1.0.0"},
            },
        )
        action_id = proposed.json()["id"]
        await client.post(
            f"/api/v1/actions/{action_id}/approve",
            headers=ADMIN,
            json={"reason": "confirmed in dashboard"},
        )

        r = await client.post("/api/v1/incidents/INC-0001/postmortem", headers=ADMIN)
        assert r.status_code == 201
        body = r.json()
        assert body["status"] == "draft"
        assert body["generated_sections"] == [
            "summary",
            "impact",
            "timeline",
            "root_cause",
            "evidence",
            "remediation",
        ]
        md = body["markdown"]
        assert "INC-0042" not in md  # sanity: not hardcoded, it's this incident's id
        assert "INC-0001" in md
        assert "[AI, MOCK provider]" in md
        assert "not confirmed facts" in md
        assert "rollback-deployment" in md
        assert "approved by user:bootstrap-admin" in md
        assert "confirmed in dashboard" in md
        assert "Not yet written" in md  # human sections seeded with placeholders

        incident = (await client.get("/api/v1/incidents/INC-0001", headers=ADMIN)).json()
        assert incident["timeline"][-1]["kind"] == "postmortem.generated"

    async def test_regenerate_preserves_human_edited_sections(
        self,
        client: httpx.AsyncClient,
        container: Any,
        clock: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        await deploy_alert_and_investigate(client, container, clock, am_alert, am_payload)
        first = (await client.post("/api/v1/incidents/INC-0001/postmortem", headers=ADMIN)).json()
        edited_md = first["markdown"].replace(
            "_Not yet written. What went well, what didn't, what was lucky?_",
            "We learned to watch error burn rate more closely.",
        )
        await client.put(
            "/api/v1/incidents/INC-0001/postmortem", headers=ADMIN, json={"markdown": edited_md}
        )

        regenerated = (
            await client.post("/api/v1/incidents/INC-0001/postmortem", headers=ADMIN)
        ).json()
        assert "We learned to watch error burn rate more closely." in regenerated["markdown"]


class TestEditAndFinalize:
    async def test_edit_replaces_the_document(
        self,
        client: httpx.AsyncClient,
        container: Any,
        clock: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        await deploy_alert_and_investigate(client, container, clock, am_alert, am_payload)
        await client.post("/api/v1/incidents/INC-0001/postmortem", headers=ADMIN)
        r = await client.put(
            "/api/v1/incidents/INC-0001/postmortem",
            headers=ADMIN,
            json={"markdown": "# Hand-written postmortem\n\nReplaced entirely."},
        )
        assert r.status_code == 200
        assert r.json()["markdown"] == "# Hand-written postmortem\n\nReplaced entirely."
        assert r.json()["status"] == "draft"

    async def test_finalize_locks_further_edits_and_regeneration(
        self,
        client: httpx.AsyncClient,
        container: Any,
        clock: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        await deploy_alert_and_investigate(client, container, clock, am_alert, am_payload)
        draft = (await client.post("/api/v1/incidents/INC-0001/postmortem", headers=ADMIN)).json()
        finalized = await client.put(
            "/api/v1/incidents/INC-0001/postmortem",
            headers=ADMIN,
            json={"markdown": draft["markdown"], "finalize": True},
        )
        assert finalized.status_code == 200
        assert finalized.json()["status"] == "final"
        assert finalized.json()["finalized_by"] == "user:bootstrap-admin"

        assert (
            await client.put(
                "/api/v1/incidents/INC-0001/postmortem",
                headers=ADMIN,
                json={"markdown": "trying to edit after finalize"},
            )
        ).status_code == 409
        assert (
            await client.post("/api/v1/incidents/INC-0001/postmortem", headers=ADMIN)
        ).status_code == 409

        incident = (await client.get("/api/v1/incidents/INC-0001", headers=ADMIN)).json()
        assert incident["timeline"][-1]["kind"] == "postmortem.finalized"

    async def test_edit_before_generate_is_404(
        self,
        client: httpx.AsyncClient,
        container: Any,
        clock: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        await deploy_alert_and_investigate(client, container, clock, am_alert, am_payload)
        r = await client.put(
            "/api/v1/incidents/INC-0001/postmortem", headers=ADMIN, json={"markdown": "x"}
        )
        assert r.status_code == 404


class TestRBAC:
    async def test_viewer_can_read_but_not_generate_or_edit(
        self,
        client: httpx.AsyncClient,
        container: Any,
        clock: Any,
        am_alert: Factory,
        am_payload: Factory,
    ) -> None:
        from sentinel.domain.enums import Role
        from sentinel.security import generate_token, upsert_principal

        token = generate_token()
        async with container.sessions.begin() as session:
            await upsert_principal(session, container.clock, "viewer-1", Role.VIEWER, token)
        viewer = {"Authorization": f"Bearer {token}"}

        await deploy_alert_and_investigate(client, container, clock, am_alert, am_payload)
        await client.post("/api/v1/incidents/INC-0001/postmortem", headers=ADMIN)

        assert (
            await client.get("/api/v1/incidents/INC-0001/postmortem", headers=viewer)
        ).status_code == 200
        assert (
            await client.post("/api/v1/incidents/INC-0001/postmortem", headers=viewer)
        ).status_code == 403
        assert (
            await client.put(
                "/api/v1/incidents/INC-0001/postmortem", headers=viewer, json={"markdown": "x"}
            )
        ).status_code == 403
