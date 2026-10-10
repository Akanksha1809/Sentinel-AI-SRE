"""Proposing, approving, rejecting and inspecting remediation actions.

Every action is a recommendation from the runbook catalogue until an approver signs
off (`POST .../approve`); nothing reaches the actuator before that. See
docs/architecture.md §13 and the threat model (T5, T6, T8) for the controls.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from sentinel.api.deps import Approver, ContainerDep, Responder, Viewer
from sentinel.api.routes.incidents import resolve_id
from sentinel.persistence.models import ActionRequest
from sentinel.remediation.service import ActionNotFoundError

router = APIRouter(prefix="/api/v1", tags=["actions"])


class ApprovalOut(BaseModel):
    principal: str
    decision: str
    reason: str | None
    decided_at: datetime


class ExecutionOut(BaseModel):
    attempt: int
    started_at: datetime
    finished_at: datetime | None
    outcome: str
    error: str | None


class VerificationOut(BaseModel):
    criteria: dict[str, Any]
    samples: list[dict[str, Any]]
    passed: bool | None
    started_at: datetime
    finished_at: datetime | None


class ActionRequestOut(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    investigation_id: uuid.UUID | None
    runbook_id: str
    runbook_version: int
    runbook_sha256: str
    action_type: str
    parameters: dict[str, Any]
    params_sha256: str
    status: str
    source: str
    rationale: str
    cited_evidence: list[str]
    requested_by: str
    dry_run: bool
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    approvals: list[ApprovalOut]
    executions: list[ExecutionOut]
    verifications: list[VerificationOut]

    @classmethod
    def of(cls, row: ActionRequest) -> ActionRequestOut:
        return cls(
            id=row.id,
            incident_id=row.incident_id,
            investigation_id=row.investigation_id,
            runbook_id=row.runbook_id,
            runbook_version=row.runbook_version,
            runbook_sha256=row.runbook_sha256,
            action_type=row.action_type,
            parameters=row.parameters,
            params_sha256=row.params_sha256,
            status=row.status,
            source=row.source,
            rationale=row.rationale,
            cited_evidence=list(row.cited_evidence),
            requested_by=row.requested_by,
            dry_run=row.dry_run,
            created_at=row.created_at,
            updated_at=row.updated_at,
            expires_at=row.expires_at,
            approvals=[
                ApprovalOut(
                    principal=a.principal,
                    decision=a.decision,
                    reason=a.reason,
                    decided_at=a.decided_at,
                )
                for a in row.approvals
            ],
            executions=[
                ExecutionOut(
                    attempt=e.attempt,
                    started_at=e.started_at,
                    finished_at=e.finished_at,
                    outcome=e.outcome,
                    error=e.error,
                )
                for e in row.executions
            ],
            verifications=[
                VerificationOut(
                    criteria=v.criteria,
                    samples=v.samples,
                    passed=v.passed,
                    started_at=v.started_at,
                    finished_at=v.finished_at,
                )
                for v in row.verifications
            ],
        )


_LOAD = (
    selectinload(ActionRequest.approvals),
    selectinload(ActionRequest.executions),
    selectinload(ActionRequest.verifications),
)


async def _load(session: AsyncSession, action_id: uuid.UUID) -> ActionRequest:
    row = (
        await session.execute(
            select(ActionRequest).where(ActionRequest.id == action_id).options(*_LOAD)
        )
    ).scalar_one_or_none()
    if row is None:
        raise ActionNotFoundError(str(action_id))
    return row


class ProposeIn(BaseModel):
    runbook_id: str = Field(max_length=64)
    parameters: dict[str, Any] = Field(default_factory=dict, max_length=8)
    rationale: str = Field(default="", max_length=2000)


class RejectIn(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)


class ApproveIn(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)


@router.post("/incidents/{ref}/actions", status_code=201, response_model=ActionRequestOut)
async def propose_action(
    ref: str, body: ProposeIn, container: ContainerDep, who: Responder
) -> ActionRequestOut:
    async with container.sessions.begin() as session:
        iid = await resolve_id(session, ref)
        row, _created = await container.actions.propose(
            session,
            iid,
            body.runbook_id,
            body.parameters,
            source="human",
            requested_by=who.actor,
            rationale=body.rationale,
        )
        full = await _load(session, row.id)
        return ActionRequestOut.of(full)


@router.get("/incidents/{ref}/actions", response_model=list[ActionRequestOut])
async def list_actions(ref: str, container: ContainerDep, _: Viewer) -> list[ActionRequestOut]:
    async with container.sessions() as session:
        iid = await resolve_id(session, ref)
        rows = (
            (
                await session.execute(
                    select(ActionRequest)
                    .where(ActionRequest.incident_id == iid)
                    .options(*_LOAD)
                    .order_by(ActionRequest.created_at.desc())
                )
            )
            .scalars()
            .all()
        )
        return [ActionRequestOut.of(r) for r in rows]


@router.get("/actions/{action_id}", response_model=ActionRequestOut)
async def get_action(action_id: uuid.UUID, container: ContainerDep, _: Viewer) -> ActionRequestOut:
    async with container.sessions() as session:
        return ActionRequestOut.of(await _load(session, action_id))


@router.post("/actions/{action_id}/approve", response_model=ActionRequestOut)
async def approve_action(
    action_id: uuid.UUID, body: ApproveIn, container: ContainerDep, who: Approver
) -> ActionRequestOut:
    async with container.sessions.begin() as session:
        await container.actions.approve(session, action_id, who.actor, body.reason)
        return ActionRequestOut.of(await _load(session, action_id))


@router.post("/actions/{action_id}/reject", response_model=ActionRequestOut)
async def reject_action(
    action_id: uuid.UUID, body: RejectIn, container: ContainerDep, who: Approver
) -> ActionRequestOut:
    async with container.sessions.begin() as session:
        await container.actions.reject(session, action_id, who.actor, body.reason)
        return ActionRequestOut.of(await _load(session, action_id))
