"""Alert ingestion, dedupe, grouping, reopen window and lifecycle against real Postgres."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import func, select

from sentinel.domain.enums import EventKind, IncidentStatus
from sentinel.domain.incidents import InvalidTransitionError
from sentinel.ingestion.alertmanager import AMWebhook, normalize
from sentinel.persistence.models import Alert, AuditEvent, Incident, IncidentEvent

pytestmark = pytest.mark.integration

Factory = Callable[..., dict[str, Any]]


async def ingest(container: Any, payload: dict[str, Any]) -> Any:
    alerts = normalize(AMWebhook.model_validate(payload), "local")
    async with container.sessions.begin() as session:
        return await container.incidents.ingest(session, alerts)


async def incidents(container: Any) -> list[Incident]:
    async with container.sessions() as session:
        return list((await session.execute(select(Incident).order_by(Incident.number))).scalars())


async def events(container: Any, incident: Incident) -> list[str]:
    async with container.sessions() as session:
        rows = await session.execute(
            select(IncidentEvent.kind)
            .where(IncidentEvent.incident_id == incident.id)
            .order_by(IncidentEvent.seq)
        )
        return list(rows.scalars())


async def test_firing_alert_opens_incident(
    container: Any, am_alert: Factory, am_payload: Factory
) -> None:
    result = await ingest(container, am_payload(am_alert()))
    [inc] = await incidents(container)
    assert result.incidents == {inc.id: "created"}
    assert (inc.short_id, inc.service, inc.status, inc.severity) == (
        "INC-0001",
        "shop-api",
        "open",
        "critical",
    )
    assert await events(container, inc) == ["incident.opened", "alert.attached"]
    async with container.sessions() as session:
        audit = (await session.execute(select(AuditEvent.action))).scalars().all()
    assert audit == ["incident.created"]


async def test_repeat_notifications_are_deduplicated(
    container: Any, am_alert: Factory, am_payload: Factory
) -> None:
    for _ in range(5):
        await ingest(container, am_payload(am_alert()))
    async with container.sessions() as session:
        alerts = (await session.execute(select(Alert))).scalars().all()
    assert len(alerts) == 1
    assert alerts[0].receive_count == 5
    assert len(await incidents(container)) == 1


async def test_related_alerts_group_and_escalate(
    container: Any, am_alert: Factory, am_payload: Factory
) -> None:
    await ingest(container, am_payload(am_alert("ShopApiHighLatency", severity="warning")))
    await ingest(container, am_payload(am_alert("ShopApiHighErrorBurnRate", severity="critical")))
    [inc] = await incidents(container)
    assert inc.severity == "critical"
    assert EventKind.INCIDENT_SEVERITY_CHANGED.value in await events(container, inc)


async def test_different_services_get_different_incidents(
    container: Any, am_alert: Factory, am_payload: Factory
) -> None:
    await ingest(container, am_payload(am_alert(service="shop-api"), am_alert(service="payments")))
    assert sorted(i.service for i in await incidents(container)) == ["payments", "shop-api"]


async def test_resolution_of_all_alerts_does_not_resolve_incident(
    container: Any, am_alert: Factory, am_payload: Factory
) -> None:
    await ingest(container, am_payload(am_alert()))
    await ingest(container, am_payload(am_alert(status="resolved")))
    [inc] = await incidents(container)
    assert inc.status == IncidentStatus.OPEN.value  # recovery must be verified, not inferred
    kinds = await events(container, inc)
    assert kinds[-2:] == ["alert.resolved", "incident.all_alerts_resolved"]


async def test_reopen_within_window_and_new_incident_after(
    container: Any, clock: Any, am_alert: Factory, am_payload: Factory
) -> None:
    await ingest(container, am_payload(am_alert()))
    [inc] = await incidents(container)
    async with container.sessions.begin() as session:
        await container.incidents.transition(
            session, inc.id, IncidentStatus.RESOLVED, "user:alice", reason="rolled back"
        )
    # Re-fires 5 minutes later (new startsAt -> new alert identity): reopen.
    clock.advance(minutes=5)
    result = await ingest(container, am_payload(am_alert(starts_at=clock.now())))
    assert result.incidents == {inc.id: "reopened"}
    [reopened] = await incidents(container)
    assert reopened.status == "open"
    assert reopened.resolved_at is None
    # Resolve again, then fire again after the 10 minute window: new incident.
    async with container.sessions.begin() as session:
        await container.incidents.transition(
            session, inc.id, IncidentStatus.RESOLVED, "user:alice", reason="fixed"
        )
    clock.advance(minutes=11)
    await ingest(container, am_payload(am_alert(starts_at=clock.now())))
    assert [i.short_id for i in await incidents(container)] == ["INC-0001", "INC-0002"]


async def test_concurrent_deliveries_never_duplicate_incidents(
    container: Any, am_alert: Factory, am_payload: Factory
) -> None:
    payloads = [am_payload(am_alert(f"Alert{i}")) for i in range(8)]
    await asyncio.gather(*(ingest(container, p) for p in payloads))
    [inc] = await incidents(container)
    async with container.sessions() as session:
        attached = (
            await session.execute(
                select(func.count()).select_from(Alert).where(Alert.incident_id == inc.id)
            )
        ).scalar_one()
    assert attached == 8


async def test_resolved_alert_never_seen_firing_is_stored(
    container: Any, am_alert: Factory, am_payload: Factory
) -> None:
    await ingest(container, am_payload(am_alert(status="resolved")))
    assert await incidents(container) == []
    async with container.sessions() as session:
        assert (await session.execute(select(func.count()).select_from(Alert))).scalar() == 1


class TestLifecycle:
    async def test_acknowledge_is_idempotent_and_audited(
        self, container: Any, am_alert: Factory, am_payload: Factory
    ) -> None:
        await ingest(container, am_payload(am_alert()))
        [inc] = await incidents(container)
        for _ in range(3):
            async with container.sessions.begin() as session:
                await container.incidents.acknowledge(session, inc.id, "user:alice")
        [inc] = await incidents(container)
        assert inc.status == "acknowledged"
        assert inc.acknowledged_by == "user:alice"
        async with container.sessions() as session:
            acks = (
                await session.execute(
                    select(func.count())
                    .select_from(AuditEvent)
                    .where(AuditEvent.action == "incident.acknowledged")
                )
            ).scalar_one()
        assert acks == 1

    async def test_manual_resolve_is_flagged_unverified(
        self, container: Any, am_alert: Factory, am_payload: Factory
    ) -> None:
        await ingest(container, am_payload(am_alert()))
        [inc] = await incidents(container)
        async with container.sessions.begin() as session:
            await container.incidents.transition(
                session, inc.id, IncidentStatus.RESOLVED, "user:alice", reason="looks fine"
            )
        [inc] = await incidents(container)
        assert (inc.status, inc.resolved_verified) == ("resolved", False)
        async with container.sessions() as session:
            summary = (
                await session.execute(
                    select(IncidentEvent.summary).order_by(IncidentEvent.seq.desc()).limit(1)
                )
            ).scalar_one()
        assert "without recovery verification" in summary

    async def test_invalid_transition_rejected(
        self, container: Any, am_alert: Factory, am_payload: Factory
    ) -> None:
        await ingest(container, am_payload(am_alert()))
        [inc] = await incidents(container)
        async with container.sessions.begin() as session:
            with pytest.raises(InvalidTransitionError):
                await container.incidents.transition(
                    session, inc.id, IncidentStatus.CLOSED, "user:alice"
                )

    async def test_stale_concurrent_update_is_detected(
        self, container: Any, am_alert: Factory, am_payload: Factory
    ) -> None:
        from sqlalchemy.orm.exc import StaleDataError

        await ingest(container, am_payload(am_alert()))
        [inc] = await incidents(container)
        async with container.sessions() as s1, container.sessions() as s2:
            a = await s1.get(Incident, inc.id)
            b = await s2.get(Incident, inc.id)
            assert a is not None
            assert b is not None
            a.title = "edited by A"
            await s1.commit()
            b.title = "edited by B"
            with pytest.raises(StaleDataError):
                await s2.commit()


def test_reopen_window_setting() -> None:
    from sentinel.config import Settings

    assert Settings(reopen_window_s=60).reopen_window == timedelta(minutes=1)
