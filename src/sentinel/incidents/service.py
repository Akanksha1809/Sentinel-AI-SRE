"""Alert ingestion, deduplication, grouping, and the incident lifecycle.

Rules:
- Alert identity is `(fingerprint, startsAt)`. Repeat notifications update the stored
  alert (receive_count, last_received_at) and never create duplicates.
- Grouping: one *active* incident per `environment/service`. Concurrent deliveries are
  serialised per key with a transaction-scoped advisory lock (a partial unique index
  backs this up).
- A firing alert for a key whose incident was resolved less than `reopen_window` ago
  reopens that incident instead of opening a new one.
- When all of an incident's alerts resolve, that is recorded as a timeline event but
  does **not** resolve the incident. Resolution requires verification (Phase 6) or an
  explicit, audited human decision flagged as unverified.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.audit import AuditLog
from sentinel.domain.enums import AlertStatus, EventKind, IncidentStatus, Severity
from sentinel.domain.incidents import ACTIVE, check_transition
from sentinel.ids import Clock
from sentinel.ingestion.alertmanager import NormalizedAlert
from sentinel.jobs.queue import JobQueue
from sentinel.observability.context import correlation_id_var
from sentinel.persistence.models import Alert, Incident, IncidentEvent

ACTIVE_VALUES = [s.value for s in ACTIVE]


class IncidentNotFoundError(LookupError):
    pass


@dataclass
class IngestResult:
    received: int = 0
    new_alerts: int = 0
    updated_alerts: int = 0
    incidents: dict[uuid.UUID, str] = field(default_factory=dict)  # id -> created|reopened|updated

    def touch(self, incident_id: uuid.UUID, outcome: str) -> None:
        # "created"/"reopened" win over "updated" for the same incident in one batch.
        if self.incidents.get(incident_id) not in ("created", "reopened"):
            self.incidents[incident_id] = outcome


class IncidentService:
    def __init__(
        self,
        clock: Clock,
        audit: AuditLog,
        reopen_window: timedelta,
        jobs: JobQueue | None = None,
        evidence_delay: timedelta = timedelta(0),
    ) -> None:
        self._clock = clock
        self._audit = audit
        self._reopen_window = reopen_window
        self._jobs = jobs
        self._evidence_delay = evidence_delay

    async def request_evidence(
        self,
        session: AsyncSession,
        incident_id: uuid.UUID,
        trigger: str,
        *,
        delay: timedelta | None = None,
    ) -> uuid.UUID | None:
        """Queue evidence collection (deduplicated per incident). None if already queued."""
        if self._jobs is None:
            return None
        return await self._jobs.enqueue(
            session,
            "evidence.collect",
            {"incident_id": str(incident_id), "trigger": trigger},
            dedupe_key=f"evidence.collect:{incident_id}",
            delay=self._evidence_delay if delay is None else delay,
        )

    async def _is_new_alertname(
        self, session: AsyncSession, incident_id: uuid.UUID, alertname: str, exclude: uuid.UUID
    ) -> bool:
        existing = (
            await session.execute(
                select(func.count())
                .select_from(Alert)
                .where(
                    Alert.incident_id == incident_id,
                    Alert.alertname == alertname,
                    Alert.id != exclude,
                )
            )
        ).scalar_one()
        return existing == 0

    async def record_event(
        self,
        session: AsyncSession,
        incident_id: uuid.UUID,
        kind: EventKind,
        actor: str,
        summary: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        incident = await self.get(session, incident_id)
        self._event(session, incident, kind, actor, summary, data)
        incident.updated_at = self._clock.now()
        await session.flush()

    # ------------------------------------------------------------------ helpers
    def _event(
        self,
        session: AsyncSession,
        incident: Incident,
        kind: EventKind,
        actor: str,
        summary: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        session.add(
            IncidentEvent(
                incident_id=incident.id,
                at=self._clock.now(),
                kind=kind.value,
                actor=actor[:80],
                summary=summary[:500],
                data=data or {},
                correlation_id=correlation_id_var.get(),
            )
        )

    async def get(
        self, session: AsyncSession, incident_id: uuid.UUID, *, for_update: bool = False
    ) -> Incident:
        stmt = select(Incident).where(Incident.id == incident_id)
        if for_update:
            stmt = stmt.with_for_update()
        incident = (await session.execute(stmt)).scalar_one_or_none()
        if incident is None:
            raise IncidentNotFoundError(str(incident_id))
        return incident

    async def _lock_key(self, session: AsyncSession, key: str) -> None:
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:k, 0))"), {"k": f"incident:{key}"}
        )

    async def _active_for(self, session: AsyncSession, key: str) -> Incident | None:
        return (
            await session.execute(
                select(Incident).where(
                    Incident.dedupe_key == key, Incident.status.in_(ACTIVE_VALUES)
                )
            )
        ).scalar_one_or_none()

    async def _recently_resolved(
        self, session: AsyncSession, key: str, now: datetime
    ) -> Incident | None:
        return (
            await session.execute(
                select(Incident)
                .where(
                    Incident.dedupe_key == key,
                    Incident.status == IncidentStatus.RESOLVED.value,
                    Incident.resolved_at >= now - self._reopen_window,
                )
                .order_by(Incident.resolved_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

    # ------------------------------------------------------------------ ingestion
    async def ingest(
        self, session: AsyncSession, alerts: list[NormalizedAlert], actor: str = "alertmanager"
    ) -> IngestResult:
        result = IngestResult(received=len(alerts))
        # Lock keys in sorted order to avoid deadlocks between concurrent batches.
        for key in sorted({a.dedupe_key for a in alerts}):
            await self._lock_key(session, key)
        for na in alerts:
            await self._ingest_one(session, na, actor, result)
        await session.flush()
        return result

    async def _ingest_one(
        self, session: AsyncSession, na: NormalizedAlert, actor: str, result: IngestResult
    ) -> None:
        now = self._clock.now()
        alert = (
            await session.execute(
                select(Alert)
                .where(Alert.fingerprint == na.fingerprint, Alert.starts_at == na.starts_at)
                .with_for_update()
            )
        ).scalar_one_or_none()
        previous_status = alert.status if alert else None
        if alert is None:
            alert = Alert(
                fingerprint=na.fingerprint,
                starts_at=na.starts_at,
                status=na.status.value,
                alertname=na.alertname,
                service=na.service,
                severity=na.severity.value,
                summary=na.summary,
                labels=na.labels,
                annotations=na.annotations,
                generator_url=na.generator_url,
                ends_at=na.ends_at,
                first_received_at=now,
                last_received_at=now,
                receive_count=1,
            )
            session.add(alert)
            result.new_alerts += 1
        else:
            alert.status = na.status.value
            alert.ends_at = na.ends_at
            alert.annotations = na.annotations
            alert.summary = na.summary
            alert.last_received_at = now
            alert.receive_count += 1
            result.updated_alerts += 1

        incident = await self.get(session, alert.incident_id) if alert.incident_id else None

        if na.status is AlertStatus.FIRING:
            if incident is None or incident.status not in ACTIVE_VALUES:
                incident, outcome = await self._incident_for(session, na, actor, now)
                alert.incident_id = incident.id
                await session.flush()
                self._event(
                    session,
                    incident,
                    EventKind.ALERT_ATTACHED,
                    actor,
                    f"{na.alertname} firing: {na.summary}",
                    {
                        "alert_id": str(alert.id),
                        "fingerprint": na.fingerprint,
                        "severity": na.severity.value,
                    },
                )
                result.touch(incident.id, outcome)
                if outcome == "created":
                    trigger = "incident.created"
                elif outcome == "reopened":  # refocus on the alert that reopened it
                    trigger = f"incident.reopened:{na.alertname}"
                elif await self._is_new_alertname(session, incident.id, na.alertname, alert.id):
                    trigger = f"alert.new:{na.alertname}"  # a different problem: refocus
                else:
                    trigger = f"alert.attached:{na.alertname}"
                await self.request_evidence(session, incident.id, trigger)
            elif previous_status == AlertStatus.RESOLVED.value:
                self._event(
                    session,
                    incident,
                    EventKind.ALERT_REFIRED,
                    actor,
                    f"{na.alertname} firing again",
                    {"alert_id": str(alert.id)},
                )
                result.touch(incident.id, "updated")
            self._escalate(session, incident, na.severity, actor)
            incident.updated_at = now
            return

        # Resolved notification.
        if incident is None:
            # Never saw this alert fire (e.g. Sentinel was down). Keep it on any active
            # incident for the key so the timeline is complete; otherwise store unattached.
            incident = await self._active_for(session, na.dedupe_key)
            if incident is None:
                return
            alert.incident_id = incident.id
        if previous_status != AlertStatus.RESOLVED.value:
            self._event(
                session,
                incident,
                EventKind.ALERT_RESOLVED,
                actor,
                f"{na.alertname} resolved",
                {"alert_id": str(alert.id)},
            )
            result.touch(incident.id, "updated")
            await session.flush()
            still_firing = (
                await session.execute(
                    select(func.count())
                    .select_from(Alert)
                    .where(
                        Alert.incident_id == incident.id, Alert.status == AlertStatus.FIRING.value
                    )
                )
            ).scalar_one()
            if still_firing == 0 and incident.status in ACTIVE_VALUES:
                self._event(
                    session,
                    incident,
                    EventKind.ALL_ALERTS_RESOLVED,
                    actor,
                    "All alerts resolved. The incident stays open until recovery "
                    "is verified or a responder resolves it.",
                )
            incident.updated_at = now

    async def _incident_for(
        self, session: AsyncSession, na: NormalizedAlert, actor: str, now: datetime
    ) -> tuple[Incident, str]:
        active = await self._active_for(session, na.dedupe_key)
        if active is not None:
            return active, "updated"
        recent = await self._recently_resolved(session, na.dedupe_key, now)
        if recent is not None:
            check_transition(IncidentStatus(recent.status), IncidentStatus.OPEN)
            recent.status = IncidentStatus.OPEN.value
            recent.resolved_at = None
            recent.resolution = None
            recent.resolved_verified = False
            recent.updated_at = now
            self._event(
                session,
                recent,
                EventKind.INCIDENT_REOPENED,
                actor,
                f"Reopened: {na.alertname} fired within the reopen window",
            )
            await self._audit.append(
                session,
                actor=actor,
                action="incident.reopened",
                subject_type="incident",
                subject_id=recent.id,
                data={"alertname": na.alertname},
            )
            return recent, "reopened"
        incident = Incident(
            service=na.service,
            environment=na.environment,
            dedupe_key=na.dedupe_key,
            title=na.summary,
            status=IncidentStatus.OPEN.value,
            severity=na.severity.value,
            opened_at=now,
            updated_at=now,
        )
        session.add(incident)
        await session.flush()  # assigns number from the sequence
        await session.refresh(incident, ["number"])
        self._event(
            session,
            incident,
            EventKind.INCIDENT_OPENED,
            actor,
            f"{incident.short_id} opened by {na.alertname}",
            {"service": na.service, "environment": na.environment},
        )
        await self._audit.append(
            session,
            actor=actor,
            action="incident.created",
            subject_type="incident",
            subject_id=incident.id,
            data={
                "short_id": incident.short_id,
                "service": na.service,
                "severity": na.severity.value,
                "alertname": na.alertname,
            },
        )
        return incident, "created"

    def _escalate(
        self, session: AsyncSession, incident: Incident, severity: Severity, actor: str
    ) -> None:
        current = Severity(incident.severity)
        if severity.rank > current.rank:
            incident.severity = severity.value
            self._event(
                session,
                incident,
                EventKind.INCIDENT_SEVERITY_CHANGED,
                actor,
                f"Severity raised {current} → {severity}",
                {"from": current.value, "to": severity.value},
            )

    # ------------------------------------------------------------------ lifecycle
    async def transition(
        self,
        session: AsyncSession,
        incident_id: uuid.UUID,
        target: IncidentStatus,
        actor: str,
        *,
        reason: str | None = None,
        verified: bool = False,
    ) -> Incident:
        incident = await self.get(session, incident_id, for_update=True)
        current = IncidentStatus(incident.status)
        check_transition(current, target)
        now = self._clock.now()
        incident.status = target.value
        incident.updated_at = now
        if target is IncidentStatus.ACKNOWLEDGED:
            incident.acknowledged_at, incident.acknowledged_by = now, actor[:80]
        elif target is IncidentStatus.RESOLVED:
            incident.resolved_at, incident.resolution = now, reason
            incident.resolved_verified = verified
        elif target is IncidentStatus.CLOSED:
            incident.closed_at = now
        summary = f"{current} → {target}" + (f": {reason}" if reason else "")
        if target is IncidentStatus.RESOLVED and not verified:
            summary += " (resolved without recovery verification)"
        self._event(
            session,
            incident,
            EventKind.INCIDENT_STATUS_CHANGED,
            actor,
            summary,
            {"from": current.value, "to": target.value, "verified": verified},
        )
        await self._audit.append(
            session,
            actor=actor,
            action=f"incident.{target.value}",
            subject_type="incident",
            subject_id=incident.id,
            data={"from": current.value, "reason": reason, "verified": verified},
        )
        await session.flush()
        return incident

    async def acknowledge(
        self, session: AsyncSession, incident_id: uuid.UUID, actor: str, note: str | None = None
    ) -> Incident:
        """Idempotent: acknowledging an already-acknowledged incident is a no-op."""
        incident = await self.get(session, incident_id, for_update=True)
        if incident.acknowledged_at is not None:
            return incident
        return await self.transition(
            session, incident_id, IncidentStatus.ACKNOWLEDGED, actor, reason=note
        )

    async def add_note(
        self, session: AsyncSession, incident_id: uuid.UUID, actor: str, text_: str
    ) -> None:
        incident = await self.get(session, incident_id)
        self._event(session, incident, EventKind.NOTE_ADDED, actor, text_)
        await self._audit.append(
            session,
            actor=actor,
            action="incident.note_added",
            subject_type="incident",
            subject_id=incident.id,
            data={"length": len(text_)},
        )
        await session.flush()
