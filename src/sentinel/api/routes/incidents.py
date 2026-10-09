"""Incident read and lifecycle endpoints."""

from __future__ import annotations

import re
import uuid
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from sentinel.api.deps import ContainerDep, Responder, Viewer
from sentinel.api.schemas import (
    AckIn,
    AlertOut,
    EventOut,
    IncidentDetail,
    IncidentPage,
    IncidentSummary,
    NoteIn,
    ResolveIn,
    telemetry_links,
)
from sentinel.container import Container
from sentinel.domain.enums import IncidentStatus, Severity
from sentinel.incidents.service import IncidentNotFoundError
from sentinel.persistence.models import Incident

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])
_SHORT_ID = re.compile(r"^INC-(\d{1,12})$", re.IGNORECASE)


async def resolve_id(session: AsyncSession, ref: str) -> uuid.UUID:
    """Accept either the UUID or the human short id (INC-0042)."""
    if m := _SHORT_ID.match(ref):
        found = (
            await session.execute(select(Incident.id).where(Incident.number == int(m.group(1))))
        ).scalar_one_or_none()
        if found is None:
            raise IncidentNotFoundError(ref)
        return found
    try:
        return uuid.UUID(ref)
    except ValueError:
        raise IncidentNotFoundError(ref) from None


async def _detail(
    container: Container, session: AsyncSession, incident_id: uuid.UUID
) -> IncidentDetail:
    incident = (
        await session.execute(
            select(Incident)
            .where(Incident.id == incident_id)
            .options(selectinload(Incident.alerts), selectinload(Incident.events))
            .execution_options(populate_existing=True)
        )
    ).scalar_one_or_none()
    if incident is None:
        raise IncidentNotFoundError(str(incident_id))
    return IncidentDetail(
        **IncidentSummary.of(incident).model_dump(),
        resolution=incident.resolution,
        alerts=[AlertOut.of(a) for a in incident.alerts],
        timeline=[EventOut.of(e) for e in incident.events],
        links=telemetry_links(incident, container.settings, container.clock.now()),
    )


@router.get("", response_model=IncidentPage)
async def list_incidents(
    container: ContainerDep,
    _: Viewer,
    status: Annotated[list[IncidentStatus] | None, Query()] = None,
    service: Annotated[str | None, Query(pattern=r"^[a-zA-Z0-9_.:-]{1,64}$")] = None,
    severity: Severity | None = None,
    active: bool | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    cursor: Annotated[
        int | None, Query(ge=1, description="Return incidents numbered below this")
    ] = None,
) -> IncidentPage:
    stmt = select(Incident).order_by(Incident.number.desc()).limit(limit + 1)
    if status:
        stmt = stmt.where(Incident.status.in_([s.value for s in status]))
    if active is not None:
        actives = [s.value for s in IncidentStatus if s.is_active]
        stmt = stmt.where(
            Incident.status.in_(actives) if active else Incident.status.not_in(actives)
        )
    if service:
        stmt = stmt.where(Incident.service == service)
    if severity:
        stmt = stmt.where(Incident.severity == severity.value)
    if cursor:
        stmt = stmt.where(Incident.number < cursor)
    async with container.sessions() as session:
        rows = list((await session.execute(stmt)).scalars())
    more = len(rows) > limit
    rows = rows[:limit]
    return IncidentPage(
        items=[IncidentSummary.of(i) for i in rows], next_cursor=rows[-1].number if more else None
    )


@router.get("/{ref}", response_model=IncidentDetail)
async def get_incident(ref: str, container: ContainerDep, _: Viewer) -> IncidentDetail:
    async with container.sessions() as session:
        return await _detail(container, session, await resolve_id(session, ref))


@router.post("/{ref}/acknowledge", response_model=IncidentDetail)
async def acknowledge(
    ref: str, body: AckIn, container: ContainerDep, who: Responder
) -> IncidentDetail:
    async with container.sessions.begin() as session:
        iid = await resolve_id(session, ref)
        await container.incidents.acknowledge(session, iid, who.actor, body.note)
    async with container.sessions() as session:
        return await _detail(container, session, iid)


@router.post("/{ref}/resolve", response_model=IncidentDetail)
async def resolve(
    ref: str, body: ResolveIn, container: ContainerDep, who: Responder
) -> IncidentDetail:
    """Manual resolution. Recorded as *unverified*; verified resolution comes from Phase 6."""
    async with container.sessions.begin() as session:
        iid = await resolve_id(session, ref)
        await container.incidents.transition(
            session, iid, IncidentStatus.RESOLVED, who.actor, reason=body.reason, verified=False
        )
    container.metrics.incidents.labels("resolved_manual").inc()
    async with container.sessions() as session:
        return await _detail(container, session, iid)


@router.post("/{ref}/close", response_model=IncidentDetail)
async def close(ref: str, container: ContainerDep, who: Responder) -> IncidentDetail:
    async with container.sessions.begin() as session:
        iid = await resolve_id(session, ref)
        await container.incidents.transition(session, iid, IncidentStatus.CLOSED, who.actor)
    async with container.sessions() as session:
        return await _detail(container, session, iid)


@router.post("/{ref}/notes", status_code=201, response_model=IncidentDetail)
async def add_note(
    ref: str, body: NoteIn, container: ContainerDep, who: Responder
) -> IncidentDetail:
    async with container.sessions.begin() as session:
        iid = await resolve_id(session, ref)
        await container.incidents.add_note(session, iid, who.actor, body.text)
    async with container.sessions() as session:
        return await _detail(container, session, iid)
