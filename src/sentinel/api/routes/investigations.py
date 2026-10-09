"""Investigations and runbook catalogue endpoints.

Responses keep observations and AI output apart: hypotheses carry `generated: true`,
and every investigation carries a human-readable `label`, which says MOCK for the
offline provider.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from sentinel.api.deps import ContainerDep, Responder, Viewer
from sentinel.api.routes.incidents import resolve_id
from sentinel.domain.enums import EventKind
from sentinel.evidence.service import latest_collection
from sentinel.investigation.service import JOB_KIND
from sentinel.persistence.models import Investigation

router = APIRouter(prefix="/api/v1", tags=["investigations"])


class HypothesisOut(BaseModel):
    rank: int
    kind: Literal["suspected_root_cause", "alternative"]
    statement: str
    confidence: float
    cited_evidence: list[str]
    why_less_likely: str | None
    uncited: bool
    generated: bool


class InvestigationOut(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    collection_id: uuid.UUID | None
    status: str
    label: str
    provider: str
    model: str
    is_mock: bool
    prompt_version: str
    requested_by: str
    started_at: datetime
    finished_at: datetime | None
    latency_ms: int | None
    error: str | None
    summary: str | None
    hypotheses: list[HypothesisOut]
    recommended_actions: list[dict[str, Any]]
    rejected_actions: list[dict[str, Any]]
    dropped_citations: list[str]
    normalised_citations: list[str]
    next_investigative_steps: list[str]
    data_gaps: list[str]


def label_for(inv: Investigation) -> str:
    who = "MOCK provider (deterministic rules)" if inv.is_mock else f"{inv.provider}:{inv.model}"
    return f"AI-generated hypothesis, {who}. Not an observation; verify against evidence."


def to_out(inv: Investigation) -> InvestigationOut:
    report = inv.report or {}
    validation = inv.validation or {}
    return InvestigationOut(
        id=inv.id,
        incident_id=inv.incident_id,
        collection_id=inv.collection_id,
        status=inv.status,
        label=label_for(inv),
        provider=inv.provider,
        model=inv.model,
        is_mock=inv.is_mock,
        prompt_version=inv.prompt_version,
        requested_by=inv.requested_by,
        started_at=inv.started_at,
        finished_at=inv.finished_at,
        latency_ms=inv.latency_ms,
        error=inv.error,
        summary=report.get("summary"),
        hypotheses=[
            HypothesisOut(
                rank=h.rank,
                kind="suspected_root_cause" if h.rank == 0 else "alternative",
                statement=h.statement,
                confidence=h.confidence,
                cited_evidence=list(h.cited_evidence),
                why_less_likely=h.why_less_likely,
                uncited=h.uncited,
                generated=h.generated,
            )
            for h in inv.hypotheses
        ],
        recommended_actions=list(validation.get("accepted_actions", [])),
        rejected_actions=list(validation.get("rejected_actions", [])),
        dropped_citations=list(validation.get("dropped_citations", [])),
        normalised_citations=list(validation.get("normalised_citations", [])),
        next_investigative_steps=list(report.get("next_investigative_steps", [])),
        data_gaps=list(report.get("data_gaps", [])),
    )


class InvestigateIn(BaseModel):
    provider: Literal["mock", "ollama"] | None = None


class InvestigateAccepted(BaseModel):
    queued: bool
    job_id: uuid.UUID | None
    provider: str
    detail: str


@router.get("/runbooks")
async def list_runbooks(container: ContainerDep, _: Viewer) -> list[dict[str, Any]]:
    return [
        {
            **r.prompt_view(),
            "version": r.version,
            "sha256": r.sha256,
            "approval": r.approval,
            "verification": r.verification.model_dump(),
        }
        for r in container.catalog.all()
    ]


@router.get("/runbooks/{runbook_id}")
async def get_runbook(runbook_id: str, container: ContainerDep, _: Viewer) -> dict[str, Any]:
    book = container.catalog.get(runbook_id)
    if book is None:
        raise HTTPException(404, f"runbook {runbook_id!r} not found")
    return book.model_dump()


@router.post("/incidents/{ref}/investigations", status_code=202, response_model=InvestigateAccepted)
async def request_investigation(
    ref: str, body: InvestigateIn, container: ContainerDep, who: Responder
) -> InvestigateAccepted:
    settings = container.settings
    provider = body.provider or settings.investigation_provider
    if provider == "ollama" and not settings.ollama_enabled:
        raise HTTPException(
            409, "the ollama provider is not enabled (set SENTINEL_OLLAMA_ENABLED=true)"
        )
    async with container.sessions.begin() as session:
        iid = await resolve_id(session, ref)
        if await latest_collection(session, iid) is None:
            raise HTTPException(
                409, "no evidence yet; collect evidence first (POST .../evidence/refresh)"
            )
        job_id = await container.jobs.enqueue(
            session,
            JOB_KIND,
            {"incident_id": str(iid), "provider": provider, "requested_by": who.actor},
            dedupe_key=f"{JOB_KIND}:{iid}",
        )
        if job_id is not None:
            await container.incidents.record_event(
                session,
                iid,
                EventKind.INVESTIGATION_REQUESTED,
                who.actor,
                f"Investigation requested ({provider})",
            )
            await container.audit.append(
                session,
                actor=who.actor,
                action="investigation.requested",
                subject_type="incident",
                subject_id=iid,
                data={"provider": provider},
            )
    if job_id is None:
        return InvestigateAccepted(
            queued=False,
            job_id=None,
            provider=provider,
            detail="an investigation is already queued or running",
        )
    return InvestigateAccepted(queued=True, job_id=job_id, provider=provider, detail="queued")


@router.get("/incidents/{ref}/investigations", response_model=list[InvestigationOut])
async def list_investigations(
    ref: str, container: ContainerDep, _: Viewer
) -> list[InvestigationOut]:
    async with container.sessions() as session:
        iid = await resolve_id(session, ref)
        rows = (
            (
                await session.execute(
                    select(Investigation)
                    .where(Investigation.incident_id == iid)
                    .options(selectinload(Investigation.hypotheses))
                    .order_by(Investigation.started_at.desc(), Investigation.id.desc())
                )
            )
            .scalars()
            .all()
        )
    return [to_out(r) for r in rows]


@router.get("/investigations/{investigation_id}", response_model=InvestigationOut)
async def get_investigation(
    investigation_id: uuid.UUID, container: ContainerDep, _: Viewer
) -> InvestigationOut:
    async with container.sessions() as session:
        inv = (
            await session.execute(
                select(Investigation)
                .where(Investigation.id == investigation_id)
                .options(selectinload(Investigation.hypotheses))
            )
        ).scalar_one_or_none()
    if inv is None:
        raise HTTPException(404, "investigation not found")
    return to_out(inv)
