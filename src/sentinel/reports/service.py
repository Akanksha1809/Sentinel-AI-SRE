"""Postmortem generation and editing (threat model T2: AI hypotheses stay labelled
and clearly separated from the generated-but-factual sections, which are themselves
assembled from stored data — never a new model call).
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from sentinel.audit import AuditLog
from sentinel.domain.enums import EventKind
from sentinel.ids import Clock
from sentinel.incidents.service import IncidentNotFoundError, IncidentService
from sentinel.persistence.models import ActionRequest, Incident, Investigation, Postmortem
from sentinel.reports.markdown import (
    ActionFact,
    EvidenceFact,
    HypothesisFact,
    IncidentFacts,
    TimelineFact,
    build_document,
    render_evidence,
    render_impact,
    render_remediation,
    render_root_cause,
    render_summary,
    render_timeline,
)


class PostmortemNotFoundError(LookupError):
    """No draft has been generated yet for this incident."""


class PostmortemFinalizedError(RuntimeError):
    """A finalized postmortem is immutable; nothing further may change it."""


class PostmortemService:
    def __init__(self, clock: Clock, audit: AuditLog, incidents: IncidentService) -> None:
        self._clock = clock
        self._audit = audit
        self._incidents = incidents

    async def get(self, session: AsyncSession, incident_id: uuid.UUID) -> Postmortem | None:
        return (
            await session.execute(select(Postmortem).where(Postmortem.incident_id == incident_id))
        ).scalar_one_or_none()

    async def _gather(self, session: AsyncSession, incident_id: uuid.UUID) -> dict[str, Any]:
        incident = (
            await session.execute(
                select(Incident)
                .where(Incident.id == incident_id)
                .options(selectinload(Incident.alerts), selectinload(Incident.events))
            )
        ).scalar_one_or_none()
        if incident is None:
            raise IncidentNotFoundError(str(incident_id))

        investigations = (
            (
                await session.execute(
                    select(Investigation)
                    .where(
                        Investigation.incident_id == incident_id,
                        Investigation.status == "succeeded",
                    )
                    .options(selectinload(Investigation.hypotheses))
                    .order_by(Investigation.started_at)
                )
            )
            .scalars()
            .all()
        )

        actions = (
            (
                await session.execute(
                    select(ActionRequest)
                    .where(ActionRequest.incident_id == incident_id)
                    .options(
                        selectinload(ActionRequest.approvals),
                        selectinload(ActionRequest.executions),
                        selectinload(ActionRequest.verifications),
                    )
                    .order_by(ActionRequest.created_at)
                )
            )
            .scalars()
            .all()
        )

        from sentinel.evidence.service import latest_collection

        collection = await latest_collection(session, incident_id)
        primary_evidence = [
            i
            for i in (collection.items if collection else [])
            if "primary" in i.flags or i.kind == "derived"
        ]
        return {
            "incident": incident,
            "investigations": investigations,
            "actions": actions,
            "evidence": primary_evidence,
        }

    def _render(self, data: dict[str, Any]) -> tuple[str, dict[str, str]]:
        incident: Incident = data["incident"]
        facts = IncidentFacts(
            short_id=incident.short_id,
            service=incident.service,
            environment=incident.environment,
            title=incident.title,
            severity=incident.severity,
            status=incident.status,
            opened_at=incident.opened_at,
            resolved_at=incident.resolved_at,
            resolved_verified=incident.resolved_verified,
            alertnames=tuple(sorted({a.alertname for a in incident.alerts})),
        )
        timeline = [TimelineFact(e.at, e.kind, e.actor, e.summary) for e in incident.events]
        hypotheses: list[HypothesisFact] = []
        for inv in data["investigations"]:
            label = "MOCK provider" if inv.is_mock else f"{inv.provider}:{inv.model}"
            for h in inv.hypotheses:
                if h.rank == 0:  # the suspected root cause only; alternatives stay in the API
                    hypotheses.append(HypothesisFact(label, h.statement, h.confidence, h.uncited))
        evidence = [EvidenceFact(e.ref, e.title, e.summary) for e in data["evidence"]]
        actions: list[ActionFact] = []
        for a in data["actions"]:
            approval = a.approvals[-1] if a.approvals else None
            execution = a.executions[-1] if a.executions else None
            verification = a.verifications[-1] if a.verifications else None
            actions.append(
                ActionFact(
                    runbook_id=a.runbook_id,
                    status=a.status,
                    parameters=a.parameters,
                    dry_run=a.dry_run,
                    approver=approval.principal if approval else None,
                    approval_reason=approval.reason if approval else None,
                    execution_outcome=execution.outcome if execution else None,
                    verification_passed=verification.passed if verification else None,
                    verification_samples=len(verification.samples) if verification else 0,
                )
            )

        generated = {
            "summary": render_summary(facts),
            "impact": render_impact(facts),
            "timeline": render_timeline(timeline),
            "root_cause": render_root_cause(hypotheses),
            "evidence": render_evidence(evidence),
            "remediation": render_remediation(actions),
        }
        return facts.short_id, generated

    async def generate(
        self, session: AsyncSession, incident_id: uuid.UUID, actor: str
    ) -> Postmortem:
        """(Re)build the auto-generated sections from current data. Human-authored
        sections (lessons_learned, follow_ups) are preserved verbatim if present."""
        from sentinel.reports.markdown import extract_sections

        existing = await self.get(session, incident_id)
        if existing is not None and existing.status == "final":
            raise PostmortemFinalizedError(f"postmortem for {incident_id} is finalized")

        data = await self._gather(session, incident_id)
        short_id, generated = self._render(data)
        human = extract_sections(existing.markdown) if existing else {}
        markdown = build_document(
            f"Postmortem: {short_id}",
            {**generated, **{k: human[k] for k in ("lessons_learned", "follow_ups") if k in human}},
        )

        now = self._clock.now()
        if existing is None:
            existing = Postmortem(
                incident_id=incident_id,
                status="draft",
                markdown=markdown,
                generated_sections=list(generated),
                authored_by=actor,
                created_at=now,
                updated_at=now,
            )
            session.add(existing)
        else:
            existing.markdown = markdown
            existing.generated_sections = list(generated)
            existing.updated_at = now
        await session.flush()
        await self._incidents.record_event(
            session,
            incident_id,
            EventKind.POSTMORTEM_GENERATED,
            actor,
            "Postmortem draft generated/regenerated",
            {"postmortem_id": str(existing.id)},
        )
        await self._audit.append(
            session,
            actor=actor,
            action="postmortem.generated",
            subject_type="postmortem",
            subject_id=existing.id,
            data={"incident_id": str(incident_id)},
        )
        return existing

    async def edit(
        self,
        session: AsyncSession,
        incident_id: uuid.UUID,
        markdown: str,
        actor: str,
        *,
        finalize: bool = False,
    ) -> Postmortem:
        row = await self.get(session, incident_id)
        if row is None:
            raise PostmortemNotFoundError(str(incident_id))
        if row.status == "final":
            raise PostmortemFinalizedError(f"postmortem for {incident_id} is finalized")

        row.markdown = markdown[:200_000]
        row.updated_at = self._clock.now()
        await self._incidents.record_event(
            session,
            incident_id,
            EventKind.POSTMORTEM_EDITED,
            actor,
            "Postmortem edited",
            {"postmortem_id": str(row.id)},
        )
        await self._audit.append(
            session,
            actor=actor,
            action="postmortem.edited",
            subject_type="postmortem",
            subject_id=row.id,
            data={"incident_id": str(incident_id), "length": len(markdown)},
        )
        if finalize:
            row.status = "final"
            row.finalized_at = self._clock.now()
            row.finalized_by = actor
            await self._incidents.record_event(
                session,
                incident_id,
                EventKind.POSTMORTEM_FINALIZED,
                actor,
                "Postmortem finalized",
                {"postmortem_id": str(row.id)},
            )
            await self._audit.append(
                session,
                actor=actor,
                action="postmortem.finalized",
                subject_type="postmortem",
                subject_id=row.id,
                data={"incident_id": str(incident_id)},
            )
        await session.flush()
        return row
