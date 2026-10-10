"""Executing an approved action against the actuator (threat model T5, T8).

The action row is locked (`with_for_update`) while it moves through `approved` ->
`executing`, so a redelivered job (e.g. after a worker crash) and a fresh one can
never run the same action concurrently. Retries are bounded and internal to one job
run: the actuator's own idempotency (Phase 2 — calling the same rollback/scale/restart
twice is a no-op the second time) makes a crash-then-redelivery safe even across
process restarts. A terminal actuator error (unknown target, out of bounds, not
managed) fails the action immediately; it is never retried.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel.audit import AuditLog
from sentinel.domain.enums import ActionStatus, EventKind, IncidentStatus
from sentinel.ids import Clock
from sentinel.incidents.service import IncidentService
from sentinel.jobs.queue import JobQueue
from sentinel.observability.metrics import Metrics
from sentinel.persistence.models import ActionExecution, ActionRequest, Incident
from sentinel.remediation.actuator_client import (
    ActuatorClient,
    ActuatorError,
    ActuatorUnavailableError,
)
from sentinel.remediation.service import VERIFY_JOB

log = structlog.get_logger("sentinel.execution")

JOB_KIND = "action.execute"
_RUNNABLE = (ActionStatus.APPROVED.value, ActionStatus.EXECUTING.value)


class ExecutionService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        clock: Clock,
        incidents: IncidentService,
        audit: AuditLog,
        client: ActuatorClient,
        jobs: JobQueue,
        *,
        max_attempts: int = 3,
        backoff_base_s: float = 2.0,
        backoff_max_s: float = 15.0,
        metrics: Metrics | None = None,
    ) -> None:
        self._sessions = sessions
        self._clock = clock
        self._incidents = incidents
        self._audit = audit
        self._client = client
        self._jobs = jobs
        self._max_attempts = max_attempts
        self._backoff_base_s = backoff_base_s
        self._backoff_max_s = backoff_max_s
        self._metrics = metrics

    async def _call(self, row: ActionRequest, service: str) -> Any:
        p = row.parameters
        if row.action_type == "restart":
            return await self._client.restart(
                service, p.get("replica"), actor="sentinel:worker", dry_run=row.dry_run
            )
        if row.action_type == "rollback":
            return await self._client.rollback(
                service,
                p["target_version"],
                p.get("target_config_revision"),
                actor="sentinel:worker",
                dry_run=row.dry_run,
            )
        if row.action_type == "scale":
            return await self._client.scale(
                service, p["replicas"], actor="sentinel:worker", dry_run=row.dry_run
            )
        raise ActuatorError(f"unknown action_type {row.action_type!r}")

    async def execute(self, action_id: uuid.UUID) -> None:
        async with self._sessions.begin() as session:
            row = (
                await session.execute(
                    select(ActionRequest).where(ActionRequest.id == action_id).with_for_update()
                )
            ).scalar_one()
            if row.status not in _RUNNABLE:
                log.info(
                    "execution skipped: not runnable", action_id=str(action_id), status=row.status
                )
                return
            service = (
                await session.execute(
                    select(Incident.service).where(Incident.id == row.incident_id)
                )
            ).scalar_one()
            if row.status == ActionStatus.APPROVED.value:
                row.status = ActionStatus.EXECUTING.value
                row.updated_at = self._clock.now()
                await self._incidents.record_event(
                    session,
                    row.incident_id,
                    EventKind.ACTION_EXECUTING,
                    "sentinel:worker",
                    f"Executing {row.runbook_id}" + (" (dry-run)" if row.dry_run else ""),
                    {"action_id": str(row.id)},
                )

        outcome, last_error = None, None
        for attempt in range(1, self._max_attempts + 1):
            started = self._clock.now()
            try:
                result = await self._call(row, service)
            except ActuatorUnavailableError as exc:
                last_error = str(exc)
                await self._record_attempt(action_id, attempt, started, "error", None, last_error)
                log.warning(
                    "execution attempt failed (transient)",
                    action_id=str(action_id),
                    attempt=attempt,
                    error=last_error,
                )
                if attempt < self._max_attempts:
                    await asyncio.sleep(
                        min(self._backoff_base_s * 2 ** (attempt - 1), self._backoff_max_s)
                    )
                continue
            except ActuatorError as exc:
                last_error = str(exc)
                await self._record_attempt(action_id, attempt, started, "error", None, last_error)
                log.warning(
                    "execution attempt failed (terminal)",
                    action_id=str(action_id),
                    attempt=attempt,
                    error=last_error,
                )
                break
            else:
                outcome = result
                await self._record_attempt(
                    action_id,
                    attempt,
                    started,
                    "changed" if result.changed else "noop",
                    result.raw,
                    None,
                )
                break

        async with self._sessions.begin() as session:
            row = (
                await session.execute(
                    select(ActionRequest).where(ActionRequest.id == action_id).with_for_update()
                )
            ).scalar_one()
            if outcome is not None:
                row.status = ActionStatus.VERIFYING.value
                row.updated_at = self._clock.now()
                await self._incidents.record_event(
                    session,
                    row.incident_id,
                    EventKind.ACTION_EXECUTED,
                    "sentinel:worker",
                    f"{row.runbook_id} executed ({'changed' if outcome.changed else 'no-op'}); "
                    "verifying recovery",
                    {"action_id": str(row.id), "plan": outcome.plan},
                )
                await self._audit.append(
                    session,
                    actor="sentinel:worker",
                    action="action.executed",
                    subject_type="action_request",
                    subject_id=row.id,
                    data={"changed": outcome.changed, "plan": outcome.plan, "dry_run": row.dry_run},
                )
                await self._incidents.try_transition(
                    session,
                    row.incident_id,
                    IncidentStatus.VERIFYING,
                    "sentinel:worker",
                    reason=f"{row.runbook_id} executed",
                )
                await self._jobs.enqueue(
                    session,
                    VERIFY_JOB,
                    {"action_id": str(row.id)},
                    dedupe_key=f"{VERIFY_JOB}:{row.id}",
                )
            else:
                row.status = ActionStatus.FAILED.value
                row.updated_at = self._clock.now()
                await self._incidents.record_event(
                    session,
                    row.incident_id,
                    EventKind.ACTION_EXECUTION_FAILED,
                    "sentinel:worker",
                    f"{row.runbook_id} failed to execute: {last_error}",
                    {"action_id": str(row.id)},
                )
                await self._audit.append(
                    session,
                    actor="sentinel:worker",
                    action="action.execution_failed",
                    subject_type="action_request",
                    subject_id=row.id,
                    data={"error": last_error},
                )
        log.info(
            "execution finished",
            action_id=str(action_id),
            outcome="verifying" if outcome is not None else "failed",
        )

    async def _record_attempt(
        self,
        action_id: uuid.UUID,
        attempt: int,
        started: Any,
        outcome: str,
        raw: dict[str, Any] | None,
        error: str | None,
    ) -> None:
        async with self._sessions.begin() as session:
            session.add(
                ActionExecution(
                    action_request_id=action_id,
                    attempt=attempt,
                    started_at=started,
                    finished_at=self._clock.now(),
                    outcome=outcome,
                    actuator_response=raw,
                    error=error[:4000] if error else None,
                )
            )
        if self._metrics is not None:
            self._metrics.action_executions.labels(outcome).inc()

    async def handle_job(self, payload: dict[str, Any]) -> None:
        await self.execute(uuid.UUID(str(payload["action_id"])))
