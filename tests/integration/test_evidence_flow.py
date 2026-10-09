"""Alert → job → worker → evidence persisted → API, against real Postgres."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from datetime import datetime
from typing import Any

import httpx
import pytest
from conftest import ADMIN_TOKEN, WEBHOOK_TOKEN, PgInfo
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import ProgrammingError

from sentinel.evidence.collector import EvidenceCollector
from sentinel.evidence.model import LogLine, Point, Series
from sentinel.evidence.service import JOB_KIND, EvidenceService
from sentinel.jobs.worker import Worker
from sentinel.main import bootstrap_admin, create_app
from sentinel.persistence.models import Job

pytestmark = pytest.mark.integration
Factory = Callable[..., dict[str, Any]]
ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


class StaticTelemetry:
    """Returns the same small dataset for every query (shape is all that matters here)."""

    async def query_range(
        self, query: str, start: datetime, end: datetime, step_s: float
    ) -> list[Series]:
        return [
            Series(
                {"service": "shop-api", "version": "1.1.0", "replica": "1"},
                tuple(
                    Point(start.timestamp() + 15 * i, 0.0 if i < 100 else 0.2) for i in range(130)
                ),
            )
        ]

    async def query_instant(self, query: str, at: datetime) -> list[Series]:
        return [Series({"version": "1.1.0"}, (Point(at.timestamp(), 42.0),))]

    async def query_logs(
        self, query: str, start: datetime, end: datetime, limit: int
    ) -> list[LogLine]:
        return [
            LogLine(
                end.timestamp(),
                {"version": "1.1.0", "config_revision": "r1"},
                '{"msg": "unhandled error", "exception": "TypeError: boom"}',
            )
        ]

    async def query_log_metrics(
        self, query: str, start: datetime, end: datetime, step_s: float
    ) -> list[Series]:
        return [
            Series({"version": "1.1.0", "config_revision": "r1"}, (Point(end.timestamp(), 5.0),))
        ]


@pytest.fixture
async def client(container: Any) -> AsyncIterator[httpx.AsyncClient]:
    await bootstrap_admin(container)
    transport = httpx.ASGITransport(app=create_app(container, run_bootstrap=False))
    async with httpx.AsyncClient(transport=transport, base_url="http://sentinel") as c:
        yield c


def worker_for(container: Any) -> Worker:
    t = StaticTelemetry()
    evidence = EvidenceService(
        container.sessions,
        container.clock,
        container.incidents,
        EvidenceCollector(t, t),
        container.metrics,
    )
    return Worker(container.sessions, container.jobs, {JOB_KIND: evidence.handle_job})


async def queued(container: Any) -> list[Job]:
    async with container.sessions() as s:
        return list((await s.execute(select(Job).where(Job.status == "pending"))).scalars())


async def test_alert_queues_one_deduplicated_collection_job(
    client: httpx.AsyncClient, container: Any, am_alert: Factory, am_payload: Factory
) -> None:
    hook = {"Authorization": f"Bearer {WEBHOOK_TOKEN}"}
    await client.post("/api/v1/webhooks/alertmanager", json=am_payload(am_alert()), headers=hook)
    await client.post(
        "/api/v1/webhooks/alertmanager",
        json=am_payload(am_alert("ShopApiHighLatency")),
        headers=hook,
    )
    jobs = await queued(container)
    assert len(jobs) == 1
    assert jobs[0].kind == JOB_KIND
    assert jobs[0].payload["trigger"] == "incident.created"
    assert jobs[0].run_after > container.clock.now()  # short delay so logs are shipped


async def test_worker_collects_and_api_serves_evidence(
    client: httpx.AsyncClient,
    container: Any,
    clock: Any,
    am_alert: Factory,
    am_payload: Factory,
) -> None:
    await client.post(
        "/api/v1/webhooks/alertmanager",
        json=am_payload(am_alert()),
        headers={"Authorization": f"Bearer {WEBHOOK_TOKEN}"},
    )
    assert (
        await client.get("/api/v1/incidents/INC-0001/evidence", headers=ADMIN)
    ).status_code == 404
    clock.advance(seconds=30)
    assert await worker_for(container).run_once() is not None

    body = (await client.get("/api/v1/incidents/INC-0001/evidence", headers=ADMIN)).json()
    assert body["status"] == "complete"
    assert body["trigger"] == "incident.created"
    refs = [i["ref"] for i in body["items"]]
    assert {
        "metric.error_ratio",
        "log.errors",
        "change.deployments",
        "derived.change_correlation",
        "derived.onset",
    } <= set(refs)
    assert all(i["kind"] != "hypothesis" for i in body["items"])  # observations only
    timeline = (await client.get("/api/v1/incidents/INC-0001", headers=ADMIN)).json()["timeline"]
    assert timeline[-1]["kind"] == "evidence.collected"
    assert timeline[-1]["actor"] == "sentinel:worker"


async def test_refresh_is_deduplicated_and_audited(
    client: httpx.AsyncClient,
    container: Any,
    clock: Any,
    am_alert: Factory,
    am_payload: Factory,
) -> None:
    await client.post(
        "/api/v1/webhooks/alertmanager",
        json=am_payload(am_alert()),
        headers={"Authorization": f"Bearer {WEBHOOK_TOKEN}"},
    )
    clock.advance(seconds=30)
    await worker_for(container).run_once()  # drain the automatic job

    first = await client.post("/api/v1/incidents/INC-0001/evidence/refresh", headers=ADMIN)
    second = await client.post("/api/v1/incidents/INC-0001/evidence/refresh", headers=ADMIN)
    assert first.status_code == 202
    assert first.json()["queued"] is True
    assert second.json()["queued"] is False
    await worker_for(container).run_once()
    audit = (await client.get("/api/v1/audit", headers=ADMIN)).json()
    assert [e["action"] for e in audit].count("evidence.refresh_requested") == 1
    evidence = (await client.get("/api/v1/incidents/INC-0001/evidence", headers=ADMIN)).json()
    assert evidence["trigger"] == "manual:user:bootstrap-admin"


async def test_viewer_cannot_request_refresh(
    client: httpx.AsyncClient, container: Any, am_alert: Factory, am_payload: Factory
) -> None:
    from sentinel.domain.enums import Role
    from sentinel.security import upsert_principal

    async with container.sessions.begin() as s:
        await upsert_principal(s, container.clock, "v", Role.VIEWER, "snt_viewer_tok_000000000")
    await client.post(
        "/api/v1/webhooks/alertmanager",
        json=am_payload(am_alert()),
        headers={"Authorization": f"Bearer {WEBHOOK_TOKEN}"},
    )
    r = await client.post(
        "/api/v1/incidents/INC-0001/evidence/refresh",
        headers={"Authorization": "Bearer snt_viewer_tok_000000000"},
    )
    assert r.status_code == 403


@pytest.mark.parametrize(
    "statement",
    ["UPDATE evidence_items SET summary = 'forged'", "DELETE FROM evidence_collections"],
)
def test_recorded_evidence_is_immutable_for_the_app_role(clean_db: PgInfo, statement: str) -> None:
    engine = create_engine(clean_db.app_url)
    with engine.connect() as conn, pytest.raises(ProgrammingError, match="permission denied"):
        conn.execute(text(statement))
    engine.dispose()
