"""Evidence collection workflow: read context → query telemetry → persist atomically.

Telemetry queries run outside any database transaction (they can take seconds), and
results are written in one short transaction together with the timeline event.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from sentinel.domain.enums import EventKind
from sentinel.evidence.analysis import ChangeCandidate
from sentinel.evidence.collector import (
    CHANGE_LOOKBACK,
    LOOKBACK,
    EvidenceCollector,
    IncidentContext,
)
from sentinel.ids import Clock
from sentinel.incidents.service import IncidentNotFoundError, IncidentService
from sentinel.observability.metrics import Metrics
from sentinel.persistence.models import (
    Deployment,
    EvidenceCollection,
    EvidenceItem,
    Incident,
)

log = structlog.get_logger("sentinel.evidence")

JOB_KIND = "evidence.collect"


def job_dedupe_key(incident_id: uuid.UUID | str) -> str:
    return f"{JOB_KIND}:{incident_id}"


class EvidenceService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        clock: Clock,
        incidents: IncidentService,
        collector: EvidenceCollector,
        metrics: Metrics,
    ) -> None:
        self._sessions = sessions
        self._clock = clock
        self._incidents = incidents
        self._collector = collector
        self._metrics = metrics

    async def _context(
        self, incident_id: uuid.UUID
    ) -> tuple[IncidentContext, list[ChangeCandidate]]:
        async with self._sessions() as session:
            incident = (
                await session.execute(
                    select(Incident)
                    .where(Incident.id == incident_id)
                    .options(selectinload(Incident.alerts))
                )
            ).scalar_one_or_none()
            if incident is None:
                raise IncidentNotFoundError(str(incident_id))
            starts = [a.starts_at for a in incident.alerts] or [incident.opened_at]
            first_alert = min(starts)
            since = min(first_alert, incident.opened_at) - LOOKBACK - CHANGE_LOOKBACK
            deployments = (
                (
                    await session.execute(
                        select(Deployment)
                        .where(
                            Deployment.service == incident.service, Deployment.deployed_at >= since
                        )
                        .order_by(Deployment.deployed_at)
                    )
                )
                .scalars()
                .all()
            )
        ctx = IncidentContext(
            service=incident.service,
            opened_at=incident.opened_at,
            first_alert_at=first_alert,
            resolved_at=incident.resolved_at,
            alertnames=frozenset(a.alertname for a in incident.alerts),
        )
        changes = [
            ChangeCandidate(
                deployment_id=str(d.id),
                service=d.service,
                version=d.version,
                previous_version=d.previous_version,
                config_revision=d.config_revision,
                previous_config_revision=d.previous_config_revision,
                deployed_at=d.deployed_at,
                change_ref=d.change_ref,
                source=d.source,
            )
            for d in deployments
        ]
        return ctx, changes

    async def collect_for_incident(
        self, incident_id: uuid.UUID, trigger: str = "manual"
    ) -> uuid.UUID:
        started = self._clock.now()
        t0 = time.perf_counter()
        ctx, changes = await self._context(incident_id)
        result = await self._collector.collect(ctx, changes, self._clock.now())

        async with self._sessions.begin() as session:
            collection = EvidenceCollection(
                incident_id=incident_id,
                status=result.status,
                window_start=result.window_start,
                window_end=result.window_end,
                onset=result.onset,
                errors={"errors": result.errors},
                started_at=started,
                finished_at=self._clock.now(),
                trigger=trigger[:80],
            )
            session.add(collection)
            await session.flush()
            for position, ev in enumerate(result.items):
                session.add(
                    EvidenceItem(
                        collection_id=collection.id,
                        incident_id=incident_id,
                        position=position,
                        ref=ev.ref,
                        kind=ev.kind.value,
                        source=ev.source,
                        title=ev.title,
                        summary=ev.summary,
                        query=ev.query,
                        data=ev.data,
                        flags=sorted(f.value for f in ev.flags),
                    )
                )
            gaps = sum(1 for e in result.items if e.kind.value == "gap")
            await self._incidents.record_event(
                session,
                incident_id,
                EventKind.EVIDENCE_COLLECTED,
                "sentinel:worker",
                f"Evidence collected ({result.status}): {len(result.items)} items"
                + (f", {gaps} data gap(s)" if gaps else ""),
                {"collection_id": str(collection.id), "status": result.status, "trigger": trigger},
            )
            collection_id = collection.id

        elapsed = time.perf_counter() - t0
        self._metrics.evidence_collections.labels(result.status).inc()
        self._metrics.evidence_seconds.observe(elapsed)
        log.info(
            "evidence collected",
            incident_id=str(incident_id),
            status=result.status,
            items=len(result.items),
            errors=len(result.errors),
            seconds=round(elapsed, 2),
        )
        return collection_id

    async def handle_job(self, payload: dict[str, Any]) -> None:
        await self.collect_for_incident(
            uuid.UUID(str(payload["incident_id"])), str(payload.get("trigger", "job"))
        )


async def latest_collection(
    session: AsyncSession, incident_id: uuid.UUID, collection_id: uuid.UUID | None = None
) -> EvidenceCollection | None:
    stmt = (
        select(EvidenceCollection)
        .where(EvidenceCollection.incident_id == incident_id)
        .options(selectinload(EvidenceCollection.items))
    )
    if collection_id:
        stmt = stmt.where(EvidenceCollection.id == collection_id)
    else:
        stmt = stmt.order_by(
            EvidenceCollection.finished_at.desc(), EvidenceCollection.id.desc()
        ).limit(1)
    return (await session.execute(stmt)).scalar_one_or_none()
