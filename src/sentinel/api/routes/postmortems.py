"""Postmortem generation, editing, and finalization.

Generated sections are assembled from already-stored facts (never a new AI call);
see `sentinel.reports`. Finalizing locks the document — see `PostmortemFinalizedError`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Body
from pydantic import BaseModel, Field

from sentinel.api.deps import ContainerDep, Responder, Viewer
from sentinel.api.routes.incidents import resolve_id
from sentinel.persistence.models import Postmortem
from sentinel.reports.service import PostmortemNotFoundError

router = APIRouter(prefix="/api/v1/incidents", tags=["postmortems"])


class PostmortemOut(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    status: str
    markdown: str
    generated_sections: list[str]
    authored_by: str
    created_at: datetime
    updated_at: datetime
    finalized_at: datetime | None
    finalized_by: str | None

    @classmethod
    def of(cls, row: Postmortem) -> PostmortemOut:
        return cls(
            id=row.id,
            incident_id=row.incident_id,
            status=row.status,
            markdown=row.markdown,
            generated_sections=list(row.generated_sections),
            authored_by=row.authored_by,
            created_at=row.created_at,
            updated_at=row.updated_at,
            finalized_at=row.finalized_at,
            finalized_by=row.finalized_by,
        )


class PostmortemEditIn(BaseModel):
    markdown: str = Field(min_length=1, max_length=200_000)
    finalize: bool = False


@router.post("/{ref}/postmortem", status_code=201, response_model=PostmortemOut)
async def generate_postmortem(ref: str, container: ContainerDep, who: Responder) -> PostmortemOut:
    """Generate (or regenerate) the draft. Human-authored sections are preserved."""
    async with container.sessions.begin() as session:
        iid = await resolve_id(session, ref)
        row = await container.postmortems.generate(session, iid, who.actor)
        return PostmortemOut.of(row)


@router.get("/{ref}/postmortem", response_model=PostmortemOut)
async def get_postmortem(ref: str, container: ContainerDep, _: Viewer) -> PostmortemOut:
    async with container.sessions() as session:
        iid = await resolve_id(session, ref)
        row = await container.postmortems.get(session, iid)
        if row is None:
            raise PostmortemNotFoundError(ref)
        return PostmortemOut.of(row)


@router.put("/{ref}/postmortem", response_model=PostmortemOut)
async def edit_postmortem(
    ref: str, body: Annotated[PostmortemEditIn, Body()], container: ContainerDep, who: Responder
) -> PostmortemOut:
    """Replace the whole document. `finalize: true` locks it (audited, irreversible)."""
    async with container.sessions.begin() as session:
        iid = await resolve_id(session, ref)
        row = await container.postmortems.edit(
            session, iid, body.markdown, who.actor, finalize=body.finalize
        )
        return PostmortemOut.of(row)
