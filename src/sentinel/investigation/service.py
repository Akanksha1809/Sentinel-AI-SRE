"""Investigation workflow: evidence → provider → validation → persisted hypotheses.

- The run is recorded *before* the provider is called, so a crash leaves a visible
  `running`/`failed` record, never silence.
- Provider failures and invalid output mark the run `failed` with the reason. Mock
  output is never substituted for a failed LLM run: a fallback that looks like the
  real thing would be misleading.
- On success the incident moves to `investigating` (when it is in an earlier state).
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from sentinel.audit import AuditLog
from sentinel.domain.enums import EventKind, IncidentStatus
from sentinel.evidence.service import latest_collection
from sentinel.ids import Clock
from sentinel.incidents.service import IncidentNotFoundError, IncidentService
from sentinel.investigation.prompt import PROMPT_VERSION, build_messages, evidence_views, input_hash
from sentinel.investigation.providers import InvestigationProvider, ProviderError
from sentinel.investigation.schemas import InvestigationRequest
from sentinel.investigation.validate import ReportValidationError, validate_report
from sentinel.observability.metrics import Metrics
from sentinel.persistence.models import HypothesisRow, Incident, Investigation
from sentinel.remediation.runbooks import RunbookCatalog

log = structlog.get_logger("sentinel.investigation")

JOB_KIND = "investigation.run"


class NoEvidenceError(RuntimeError):
    """An investigation needs an evidence collection first."""


class InvestigationService:
    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        clock: Clock,
        incidents: IncidentService,
        audit: AuditLog,
        catalog: RunbookCatalog,
        providers: dict[str, InvestigationProvider],
        metrics: Metrics,
        *,
        timeout_s: float = 300.0,
    ) -> None:
        self._sessions = sessions
        self._clock = clock
        self._incidents = incidents
        self._audit = audit
        self._catalog = catalog
        self._providers = providers
        self._metrics = metrics
        self._timeout_s = timeout_s

    def provider(self, name: str) -> InvestigationProvider:
        try:
            return self._providers[name]
        except KeyError:
            raise ValueError(f"unknown or disabled investigation provider {name!r}") from None

    async def _request(
        self, incident_id: uuid.UUID
    ) -> tuple[InvestigationRequest, uuid.UUID, set[str], str]:
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
            collection = await latest_collection(session, incident_id)
            if collection is None:
                raise NoEvidenceError(f"{incident.short_id} has no evidence collection yet")
            views = evidence_views(list(collection.items))
            request = InvestigationRequest(
                incident={
                    "id": incident.short_id,
                    "service": incident.service,
                    "environment": incident.environment,
                    "title": incident.title,
                    "severity": incident.severity,
                    "status": incident.status,
                    "opened_at": incident.opened_at.isoformat(),
                    "alertnames": sorted({a.alertname for a in incident.alerts}),
                    "alerts": [
                        {
                            "alertname": a.alertname,
                            "status": a.status,
                            "severity": a.severity,
                            "summary": a.summary,
                        }
                        for a in incident.alerts
                    ][:10],
                },
                evidence=views,
                runbooks=[r.prompt_view() for r in self._catalog.all()],
                evidence_status=collection.status,
                evidence_errors=list(collection.errors.get("errors", []))[:5],
            )
        return request, collection.id, {v.ref for v in views}, incident.service

    async def run(
        self, incident_id: uuid.UUID, provider_name: str, requested_by: str = "sentinel:auto"
    ) -> uuid.UUID:
        provider = self.provider(provider_name)
        request, collection_id, refs, service = await self._request(incident_id)
        messages = build_messages(request)
        async with self._sessions.begin() as session:
            inv = Investigation(
                incident_id=incident_id,
                collection_id=collection_id,
                status="running",
                provider=provider.name,
                model=provider.model,
                is_mock=provider.is_mock,
                prompt_version=PROMPT_VERSION,
                input_hash=input_hash(messages),
                requested_by=requested_by[:120],
                started_at=self._clock.now(),
            )
            session.add(inv)
            await session.flush()
            inv_id = inv.id

        t0 = time.perf_counter()
        try:
            raw = await asyncio.wait_for(provider.investigate(request), self._timeout_s)
            usage = raw.pop("_usage", None)
            raw_copy = json.loads(json.dumps(raw, default=str))  # pre-validation snapshot
            outcome = validate_report(
                raw, evidence_refs=refs, catalog=self._catalog, service=service
            )
        except (ProviderError, ReportValidationError, TimeoutError) as exc:
            reason = "provider timed out" if isinstance(exc, TimeoutError) else str(exc)
            await self._finish_failed(
                inv_id, incident_id, provider_name, reason, time.perf_counter() - t0
            )
            return inv_id

        latency_ms = int((time.perf_counter() - t0) * 1000)
        report = outcome.report
        async with self._sessions.begin() as session:
            inv = await session.get_one(Investigation, inv_id)
            inv.status, inv.finished_at, inv.latency_ms = "succeeded", self._clock.now(), latency_ms
            inv.report = report.model_dump()
            inv.validation = {**outcome.summary(), "usage": usage, "raw_output": raw_copy}
            session.add(
                HypothesisRow(
                    investigation_id=inv_id,
                    rank=0,
                    statement=report.suspected_root_cause.statement,
                    confidence=report.suspected_root_cause.confidence,
                    cited_evidence=report.suspected_root_cause.cited_evidence,
                    uncited="suspected_root_cause" in outcome.uncited,
                )
            )
            for i, alt in enumerate(report.alternative_hypotheses, start=1):
                session.add(
                    HypothesisRow(
                        investigation_id=inv_id,
                        rank=i,
                        statement=alt.statement,
                        confidence=alt.confidence,
                        cited_evidence=alt.cited_evidence,
                        why_less_likely=alt.why_less_likely or None,
                        uncited=f"alternative_hypotheses[{i - 1}]" in outcome.uncited,
                    )
                )
            label = "MOCK" if provider.is_mock else f"{provider.name}:{provider.model}"
            await self._incidents.record_event(
                session,
                incident_id,
                EventKind.INVESTIGATION_COMPLETED,
                f"ai:{label}",
                f"[AI hypothesis, {label}] {report.suspected_root_cause.statement[:300]} "
                f"(confidence {report.suspected_root_cause.confidence:.2f})",
                {
                    "investigation_id": str(inv_id),
                    "provider": provider.name,
                    "accepted_actions": len(outcome.accepted_actions),
                    "rejected_actions": len(outcome.rejected_actions),
                },
            )
            await self._audit.append(
                session,
                actor=requested_by,
                action="investigation.completed",
                subject_type="investigation",
                subject_id=inv_id,
                data={
                    "incident_id": str(incident_id),
                    "provider": label,
                    "rejected_actions": outcome.rejected_actions,
                    "dropped_citations": outcome.dropped_citations,
                },
            )
            incident = await self._incidents.get(session, incident_id)
            if incident.status in (IncidentStatus.OPEN.value, IncidentStatus.ACKNOWLEDGED.value):
                await self._incidents.transition(
                    session,
                    incident_id,
                    IncidentStatus.INVESTIGATING,
                    "sentinel:auto",
                    reason="AI investigation completed",
                )
        self._metrics.investigations.labels(provider.name, "succeeded").inc()
        self._metrics.investigation_seconds.labels(provider.name).observe(latency_ms / 1000)
        log.info(
            "investigation completed",
            incident_id=str(incident_id),
            provider=label,
            latency_ms=latency_ms,
            confidence=report.suspected_root_cause.confidence,
            accepted=len(outcome.accepted_actions),
            rejected=len(outcome.rejected_actions),
        )
        return inv_id

    async def _finish_failed(
        self, inv_id: uuid.UUID, incident_id: uuid.UUID, provider: str, reason: str, elapsed: float
    ) -> None:
        async with self._sessions.begin() as session:
            inv = await session.get_one(Investigation, inv_id)
            inv.status, inv.finished_at, inv.error = "failed", self._clock.now(), reason[:2000]
            inv.latency_ms = int(elapsed * 1000)
            await self._incidents.record_event(
                session,
                incident_id,
                EventKind.INVESTIGATION_FAILED,
                f"ai:{provider}",
                f"Investigation failed ({provider}): {reason[:300]}",
                {"investigation_id": str(inv_id)},
            )
        self._metrics.investigations.labels(provider, "failed").inc()
        log.warning(
            "investigation failed", incident_id=str(incident_id), provider=provider, reason=reason
        )

    async def handle_job(self, payload: dict[str, Any]) -> None:
        await self.run(
            uuid.UUID(str(payload["incident_id"])),
            str(payload["provider"]),
            str(payload.get("requested_by", "sentinel:auto")),
        )
