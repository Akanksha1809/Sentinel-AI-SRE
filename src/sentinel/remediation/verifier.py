"""Recovery verification: never report recovery without checking measured signals.

After `settle_s`, each of the runbook's checks is sampled every `interval_s` for up to
`window_s`. Verification passes only once `consecutive` samples in a row have *every*
check passing; it succeeds as soon as that streak is reached, and fails if the window
runs out first. A query that errors, or returns no data, counts as a **failed** sample
for that check — recovery is never assumed from missing evidence.
"""

from __future__ import annotations

import asyncio
import operator
import time
import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sentinel.audit import AuditLog
from sentinel.domain.enums import ActionStatus, EventKind, IncidentStatus
from sentinel.evidence.clients import MetricsSource, QueryError
from sentinel.evidence.templates import label_value
from sentinel.ids import Clock
from sentinel.incidents.service import IncidentService
from sentinel.observability.metrics import Metrics
from sentinel.persistence.models import ActionRequest, Incident, Verification
from sentinel.remediation.runbooks import Check, RunbookCatalog, Signal

log = structlog.get_logger("sentinel.verifier")

JOB_KIND = "action.verify"
_RUNNABLE = (ActionStatus.VERIFYING.value,)

_OPS: dict[str, Callable[[float, float], bool]] = {
    "lt": operator.lt,
    "lte": operator.le,
    "gt": operator.gt,
    "gte": operator.ge,
    "eq": lambda a, b: abs(a - b) < 1e-6,
}

_SIGNAL_QUERIES: dict[Signal, str] = {
    "error_ratio": 'service:http_error_ratio:rate30s{{service="{svc}"}}',
    "latency_p95": 'service:http_latency_p95:rate1m{{service="{svc}"}}',
    "memory_ratio": 'service:container_memory_ratio:max{{service="{svc}"}}',
    # on(service): fleet_desired_replicas is a raw scrape (job/instance labels still
    # attached); the recording rule on the left has already dropped them. Without
    # `on(service)` the default one-to-one vector match requires identical label sets
    # and silently returns no result at all (found live: every sample read "no data").
    "replicas_ready_ratio": (
        'service:replicas_running:sum{{service="{svc}"}} / on(service) '
        'fleet_desired_replicas{{service="{svc}"}}'
    ),
    # Gauge-safe: clamp_min(delta(...), 0) ignores the drop to 0 a container recreate
    # causes, so only genuinely new restarts since (about) the action count.
    "restarts_in_window": (
        'sum(clamp_min(delta(fleet_container_restart_count{{service="{svc}"}}[{window_s}s]), 0))'
    ),
}


def render_signal_query(signal: Signal, service: str, window_s: int) -> str:
    return _SIGNAL_QUERIES[signal].format(svc=label_value(service), window_s=window_s)


class VerificationService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        clock: Clock,
        incidents: IncidentService,
        catalog: RunbookCatalog,
        audit: AuditLog,
        metrics: MetricsSource,
        *,
        app_metrics: Metrics | None = None,
    ) -> None:
        self._sessions = sessions
        self._clock = clock
        self._incidents = incidents
        self._catalog = catalog
        self._audit = audit
        self._metrics = metrics
        self._app_metrics = app_metrics

    async def _evaluate_check(self, check: Check, service: str, window_s: int) -> dict[str, Any]:
        query = render_signal_query(check.signal, service, window_s)
        try:
            series = await self._metrics.query_instant(query, self._clock.now())
        except QueryError as exc:
            return {
                "signal": check.signal,
                "op": check.op,
                "target": check.value,
                "observed": None,
                "passed": False,
                "error": str(exc),
            }
        if len(series) != 1 or not series[0].points:
            return {
                "signal": check.signal,
                "op": check.op,
                "target": check.value,
                "observed": None,
                "passed": False,
                "error": "no data" if not series else "ambiguous (multiple series)",
            }
        observed = series[0].points[-1].value
        passed = _OPS[check.op](observed, check.value)
        return {
            "signal": check.signal,
            "op": check.op,
            "target": check.value,
            "observed": observed,
            "passed": passed,
            "error": None,
        }

    async def _sample(
        self, checks: tuple[Check, ...], service: str, window_s: int, at: datetime
    ) -> dict[str, Any]:
        results = [await self._evaluate_check(c, service, window_s) for c in checks]
        return {
            "at": at.isoformat(),
            "checks": results,
            "passed": all(r["passed"] for r in results),
        }

    async def verify(self, action_id: uuid.UUID) -> None:
        async with self._sessions() as session:
            row = (
                await session.execute(select(ActionRequest).where(ActionRequest.id == action_id))
            ).scalar_one()
            if row.status not in _RUNNABLE:
                log.info(
                    "verification skipped: not runnable",
                    action_id=str(action_id),
                    status=row.status,
                )
                return
            service = (
                await session.execute(
                    select(Incident.service).where(Incident.id == row.incident_id)
                )
            ).scalar_one()
        runbook = self._catalog.get(row.runbook_id)
        if runbook is None:
            await self._finish(
                action_id, row.incident_id, [], False, error="runbook no longer in the catalogue"
            )
            return
        spec = runbook.verification
        started = self._clock.now()
        log.info(
            "verification starting",
            action_id=str(action_id),
            runbook=runbook.id,
            settle_s=spec.settle_s,
            window_s=spec.window_s,
        )
        await asyncio.sleep(spec.settle_s)

        samples: list[dict[str, Any]] = []
        streak = 0
        deadline = time.monotonic() + spec.window_s
        while True:
            sample = await self._sample(spec.checks, service, spec.window_s, self._clock.now())
            samples.append(sample)
            streak = streak + 1 if sample["passed"] else 0
            if streak >= spec.consecutive:
                passed = True
                break
            if time.monotonic() >= deadline:
                passed = False
                break
            await asyncio.sleep(spec.interval_s)

        await self._finish(
            action_id,
            row.incident_id,
            samples,
            passed,
            started=started,
            criteria=[{"signal": c.signal, "op": c.op, "value": c.value} for c in spec.checks],
        )

    async def _finish(
        self,
        action_id: uuid.UUID,
        incident_id: uuid.UUID,
        samples: list[dict[str, Any]],
        passed: bool,
        *,
        started: datetime | None = None,
        criteria: list[dict[str, Any]] | None = None,
        error: str | None = None,
    ) -> None:
        finished = self._clock.now()
        async with self._sessions.begin() as session:
            row = (
                await session.execute(
                    select(ActionRequest).where(ActionRequest.id == action_id).with_for_update()
                )
            ).scalar_one()
            session.add(
                Verification(
                    action_request_id=action_id,
                    criteria={"checks": criteria or [], "error": error},
                    samples=samples,
                    passed=passed,
                    started_at=started or finished,
                    finished_at=finished,
                )
            )
            if passed:
                row.status = ActionStatus.SUCCEEDED.value
                row.updated_at = finished
                await self._incidents.record_event(
                    session,
                    incident_id,
                    EventKind.ACTION_VERIFIED,
                    "sentinel:worker",
                    f"Recovery verified after {row.runbook_id} ({len(samples)} sample(s))",
                    {"action_id": str(action_id)},
                )
                await self._audit.append(
                    session,
                    actor="sentinel:worker",
                    action="action.verified",
                    subject_type="action_request",
                    subject_id=action_id,
                    data={"samples": len(samples)},
                )
                await self._incidents.try_transition(
                    session,
                    incident_id,
                    IncidentStatus.RESOLVED,
                    "sentinel:auto",
                    reason=f"Verified recovery after {row.runbook_id}",
                    verified=True,
                )
            else:
                row.status = ActionStatus.VERIFICATION_FAILED.value
                row.updated_at = finished
                last = samples[-1] if samples else None
                detail = error or (f"last sample: {last['checks']}" if last else "no samples")
                await self._incidents.record_event(
                    session,
                    incident_id,
                    EventKind.ACTION_VERIFICATION_FAILED,
                    "sentinel:worker",
                    f"Recovery not verified after {row.runbook_id}: {detail}",
                    {"action_id": str(action_id)},
                )
                await self._audit.append(
                    session,
                    actor="sentinel:worker",
                    action="action.verification_failed",
                    subject_type="action_request",
                    subject_id=action_id,
                    data={"samples": len(samples), "error": error},
                )
                await self._incidents.try_transition(
                    session,
                    incident_id,
                    IncidentStatus.REMEDIATING,
                    "sentinel:auto",
                    reason=f"Verification failed for {row.runbook_id}",
                )
        if self._app_metrics is not None:
            self._app_metrics.verifications.labels(str(passed).lower()).inc()
        log.info(
            "verification finished", action_id=str(action_id), passed=passed, samples=len(samples)
        )

    async def handle_job(self, payload: dict[str, Any]) -> None:
        await self.verify(uuid.UUID(str(payload["action_id"])))
