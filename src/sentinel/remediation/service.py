"""Proposing, approving and rejecting remediation actions (threat model T5, T6, T8).

An `ActionRequest` is only ever created from a runbook in the catalogue, with
parameters the runbook itself has type- and bounds-checked and pinned to the
incident's service (`Runbook.validate_parameters`, Phase 5). This service adds:
identity (idempotency, so the same proposal is never duplicated), policy (approval
requirement, rate limit, cooldown), and the approve/reject decision, which is bound to
the *exact* runbook content (`runbook_sha256`) at proposal time — if the runbook file
on disk changes before anyone approves, approval is refused and a fresh proposal is
required.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.audit import AuditLog
from sentinel.domain.actions import check_transition
from sentinel.domain.enums import ActionStatus, EventKind, IncidentStatus
from sentinel.ids import Clock
from sentinel.incidents.service import IncidentService
from sentinel.jobs.queue import JobQueue
from sentinel.observability.metrics import Metrics
from sentinel.persistence.models import ActionExecution, ActionRequest, Incident
from sentinel.persistence.models import Approval as ApprovalRow
from sentinel.remediation.policy import PolicyContext, PolicyEngine
from sentinel.remediation.runbooks import ParameterError, RunbookCatalog

EXECUTE_JOB = "action.execute"
VERIFY_JOB = "action.verify"
_ACTIVE_SQL = "status IN ('proposed','pending_approval','approved','executing','verifying')"


class ActionNotFoundError(LookupError):
    pass


class RunbookChangedError(RuntimeError):
    """The catalogue runbook no longer matches what was proposed; propose again."""


class ActionLimitExceededError(RuntimeError):
    """Rate limit refused creating a new action request for this incident."""


class ActionExpiredError(RuntimeError):
    pass


def _canon(params: dict[str, Any]) -> str:
    return json.dumps(params, sort_keys=True, separators=(",", ":"))


def params_hash(params: dict[str, Any]) -> str:
    return hashlib.sha256(_canon(params).encode()).hexdigest()


def idempotency_key(incident_id: uuid.UUID, runbook_id: str, params: dict[str, Any]) -> str:
    digest = hashlib.sha256(f"{incident_id}|{runbook_id}|{_canon(params)}".encode()).hexdigest()
    return digest[:64]


class ActionService:
    def __init__(
        self,
        clock: Clock,
        audit: AuditLog,
        incidents: IncidentService,
        catalog: RunbookCatalog,
        jobs: JobQueue,
        policy: PolicyEngine,
        *,
        expiry: timedelta = timedelta(minutes=30),
        dry_run_default: bool = True,
        metrics: Metrics | None = None,
    ) -> None:
        self._clock = clock
        self._audit = audit
        self._incidents = incidents
        self._catalog = catalog
        self._jobs = jobs
        self._policy = policy
        self._expiry = expiry
        self._dry_run_default = dry_run_default
        self._metrics = metrics

    # ------------------------------------------------------------------ reads
    async def get(
        self, session: AsyncSession, action_id: uuid.UUID, *, for_update: bool = False
    ) -> ActionRequest:
        stmt = select(ActionRequest).where(ActionRequest.id == action_id)
        if for_update:
            stmt = stmt.with_for_update()
        row = (await session.execute(stmt)).scalar_one_or_none()
        if row is None:
            raise ActionNotFoundError(str(action_id))
        return row

    async def list_for_incident(
        self, session: AsyncSession, incident_id: uuid.UUID
    ) -> list[ActionRequest]:
        return list(
            (
                await session.execute(
                    select(ActionRequest)
                    .where(ActionRequest.incident_id == incident_id)
                    .order_by(ActionRequest.created_at.desc())
                )
            ).scalars()
        )

    # ------------------------------------------------------------------ helpers
    async def _policy_context(
        self, session: AsyncSession, incident_id: uuid.UUID, runbook_id: str, service: str
    ) -> PolicyContext:
        count = (
            await session.execute(
                select(func.count())
                .select_from(ActionRequest)
                .where(ActionRequest.incident_id == incident_id)
            )
        ).scalar_one()
        last_exec = (
            await session.execute(
                select(func.max(ActionExecution.started_at))
                .join(ActionRequest, ActionExecution.action_request_id == ActionRequest.id)
                .where(
                    ActionRequest.runbook_id == runbook_id,
                    ActionRequest.incident_id.in_(
                        select(Incident.id).where(Incident.service == service)
                    ),
                )
            )
        ).scalar()
        return PolicyContext(
            existing_requests_for_incident=count, last_execution_started_at=last_exec
        )

    async def _expire_if_due(self, session: AsyncSession, row: ActionRequest) -> bool:
        """If `row` (already locked by the caller) is a stale pending_approval request,
        flip it to expired. Returns True if so."""
        if row.status != ActionStatus.PENDING_APPROVAL.value or self._clock.now() < row.expires_at:
            return False
        await self._expire_row(session, row)
        return True

    async def _expire_row(self, session: AsyncSession, row: ActionRequest) -> None:
        row.status = ActionStatus.EXPIRED.value
        row.updated_at = self._clock.now()
        await self._incidents.record_event(
            session,
            row.incident_id,
            EventKind.ACTION_EXPIRED,
            "sentinel:auto",
            f"Action request for {row.runbook_id} expired without a decision",
            {"action_id": str(row.id)},
        )
        await self._audit.append(
            session,
            actor="sentinel:auto",
            action="action.expired",
            subject_type="action_request",
            subject_id=row.id,
        )
        if self._metrics is not None:
            self._metrics.action_decisions.labels("expired").inc()

    # ------------------------------------------------------------------ propose
    async def propose(
        self,
        session: AsyncSession,
        incident_id: uuid.UUID,
        runbook_id: str,
        parameters: dict[str, Any],
        *,
        source: str,
        requested_by: str,
        investigation_id: uuid.UUID | None = None,
        cited_evidence: list[str] | None = None,
        rationale: str = "",
    ) -> tuple[ActionRequest, bool]:
        """Returns (row, created). `created=False` means an active duplicate exists
        and that existing row is returned unchanged."""
        runbook = self._catalog.get(runbook_id)
        if runbook is None:
            raise ParameterError(f"{runbook_id!r} is not in the runbook catalogue")
        incident = await self._incidents.get(session, incident_id)
        clean = runbook.validate_parameters(parameters, service=incident.service)

        ctx = await self._policy_context(session, incident_id, runbook.id, incident.service)
        if blocked := self._policy.check_rate_limit(ctx):
            raise ActionLimitExceededError(blocked)
        now = self._clock.now()
        decision = self._policy.decide_approval(runbook, ctx, now)
        status = ActionStatus.APPROVED if decision.auto_approve else ActionStatus.PENDING_APPROVAL
        key = idempotency_key(incident_id, runbook.id, clean)

        stmt = (
            insert(ActionRequest)
            .values(
                incident_id=incident_id,
                investigation_id=investigation_id,
                runbook_id=runbook.id,
                runbook_version=runbook.version,
                runbook_sha256=runbook.sha256,
                action_type=runbook.action,
                parameters=clean,
                params_sha256=params_hash(clean),
                idempotency_key=key,
                status=status.value,
                source=source,
                rationale=rationale[:2000],
                cited_evidence=cited_evidence or [],
                requested_by=requested_by[:120],
                dry_run=self._dry_run_default,
                created_at=now,
                updated_at=now,
                expires_at=now + self._expiry,
            )
            .on_conflict_do_nothing(
                index_elements=["idempotency_key"],
                index_where=text(_ACTIVE_SQL),
            )
            .returning(ActionRequest.id)
        )
        new_id = (await session.execute(stmt)).scalar_one_or_none()
        if new_id is None:
            existing = (
                await session.execute(
                    select(ActionRequest).where(
                        ActionRequest.idempotency_key == key, text(_ACTIVE_SQL)
                    )
                )
            ).scalar_one()
            return existing, False

        row = (
            await session.execute(select(ActionRequest).where(ActionRequest.id == new_id))
        ).scalar_one()
        await self._incidents.record_event(
            session,
            incident_id,
            EventKind.ACTION_PROPOSED,
            requested_by,
            f"Proposed {runbook.id} ({decision.reason}): {rationale or runbook.title}",
            {
                "action_id": str(row.id),
                "runbook_id": runbook.id,
                "parameters": clean,
                "status": status.value,
            },
        )
        await self._audit.append(
            session,
            actor=requested_by,
            action="action.proposed",
            subject_type="action_request",
            subject_id=row.id,
            data={
                "incident_id": str(incident_id),
                "runbook_id": runbook.id,
                "runbook_sha256": runbook.sha256,
                "parameters": clean,
                "auto_approved": decision.auto_approve,
            },
        )
        if self._metrics is not None:
            self._metrics.action_requests.labels(source, status.value).inc()
        if status is ActionStatus.APPROVED:
            await self._finish_approval(session, row, "policy:auto", None)
        return row, True

    # ------------------------------------------------------------------ approve / reject
    async def approve(
        self, session: AsyncSession, action_id: uuid.UUID, actor: str, reason: str | None = None
    ) -> ActionRequest:
        row = await self.get(session, action_id, for_update=True)
        if await self._expire_if_due(session, row):
            raise ActionExpiredError(f"action {action_id} expired before it was approved")
        current = self._catalog.get(row.runbook_id)
        if current is None or current.sha256 != row.runbook_sha256:
            raise RunbookChangedError(
                f"runbook {row.runbook_id!r} changed since this action was proposed; "
                "propose it again"
            )
        check_transition(ActionStatus(row.status), ActionStatus.APPROVED)
        session.add(
            ApprovalRow(
                action_request_id=row.id,
                principal=actor,
                decision="approved",
                reason=reason,
                params_sha256=row.params_sha256,
                runbook_sha256=row.runbook_sha256,
                decided_at=self._clock.now(),
            )
        )
        await self._finish_approval(session, row, actor, reason)
        return row

    async def _finish_approval(
        self, session: AsyncSession, row: ActionRequest, actor: str, reason: str | None
    ) -> None:
        row.status = ActionStatus.APPROVED.value
        row.updated_at = self._clock.now()
        await self._incidents.record_event(
            session,
            row.incident_id,
            EventKind.ACTION_APPROVED,
            actor,
            f"Approved {row.runbook_id}" + (f": {reason}" if reason else ""),
            {"action_id": str(row.id)},
        )
        await self._audit.append(
            session,
            actor=actor,
            action="action.approved",
            subject_type="action_request",
            subject_id=row.id,
            data={
                "reason": reason,
                "runbook_sha256": row.runbook_sha256,
                "params_sha256": row.params_sha256,
            },
        )
        await self._incidents.try_transition(
            session,
            row.incident_id,
            IncidentStatus.REMEDIATING,
            actor,
            reason=f"Action {row.runbook_id} approved",
        )
        await self._jobs.enqueue(
            session, EXECUTE_JOB, {"action_id": str(row.id)}, dedupe_key=f"{EXECUTE_JOB}:{row.id}"
        )
        if self._metrics is not None:
            self._metrics.action_decisions.labels("approved").inc()

    async def reject(
        self, session: AsyncSession, action_id: uuid.UUID, actor: str, reason: str
    ) -> ActionRequest:
        row = await self.get(session, action_id, for_update=True)
        if await self._expire_if_due(session, row):
            raise ActionExpiredError(f"action {action_id} expired before it was rejected")
        check_transition(ActionStatus(row.status), ActionStatus.REJECTED)
        row.status = ActionStatus.REJECTED.value
        row.updated_at = self._clock.now()
        session.add(
            ApprovalRow(
                action_request_id=row.id,
                principal=actor,
                decision="rejected",
                reason=reason,
                params_sha256=row.params_sha256,
                runbook_sha256=row.runbook_sha256,
                decided_at=self._clock.now(),
            )
        )
        await self._incidents.record_event(
            session,
            row.incident_id,
            EventKind.ACTION_REJECTED,
            actor,
            f"Rejected {row.runbook_id}: {reason}",
            {"action_id": str(row.id)},
        )
        await self._audit.append(
            session,
            actor=actor,
            action="action.rejected",
            subject_type="action_request",
            subject_id=row.id,
            data={"reason": reason},
        )
        if self._metrics is not None:
            self._metrics.action_decisions.labels("rejected").inc()
        return row

    # ------------------------------------------------------------------ maintenance
    async def expire_stale(self, session: AsyncSession) -> int:
        """Sweep pending_approval requests past their expiry. Called periodically by the
        worker, and defensively at approve()/reject() time for the specific row."""
        now = self._clock.now()
        rows = list(
            (
                await session.execute(
                    select(ActionRequest)
                    .where(
                        ActionRequest.status == ActionStatus.PENDING_APPROVAL.value,
                        ActionRequest.expires_at < now,
                    )
                    .with_for_update(skip_locked=True)
                )
            ).scalars()
        )
        for row in rows:
            await self._expire_row(session, row)
        return len(rows)
