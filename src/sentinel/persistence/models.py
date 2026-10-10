"""SQLAlchemy ORM models. Alembic migrations in `migrations/` own the DDL.

See docs/data-model.md for the entity overview and state machines.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from sentinel.ids import uuid7

NAMING = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

Json = dict[str, Any]
TS = DateTime(timezone=True)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)
    type_annotation_map = {Json: JSONB, datetime: TS, uuid.UUID: UUID(as_uuid=True)}  # noqa: RUF012


def _pk() -> Mapped[uuid.UUID]:
    return mapped_column(primary_key=True, default=uuid7)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = _pk()
    number: Mapped[int] = mapped_column(
        BigInteger, server_default=text("nextval('incident_number_seq')"), unique=True
    )
    service: Mapped[str] = mapped_column(String(64))
    environment: Mapped[str] = mapped_column(String(64))
    dedupe_key: Mapped[str] = mapped_column(String(130))
    title: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(20))
    severity: Mapped[str] = mapped_column(String(10))
    opened_at: Mapped[datetime]
    acknowledged_at: Mapped[datetime | None]
    acknowledged_by: Mapped[str | None] = mapped_column(String(80))
    resolved_at: Mapped[datetime | None]
    resolution: Mapped[str | None] = mapped_column(Text)
    resolved_verified: Mapped[bool] = mapped_column(server_default=text("false"))
    closed_at: Mapped[datetime | None]
    updated_at: Mapped[datetime]
    version: Mapped[int] = mapped_column(Integer, server_default=text("1"))

    alerts: Mapped[list[Alert]] = relationship(
        back_populates="incident", order_by="Alert.starts_at"
    )
    events: Mapped[list[IncidentEvent]] = relationship(
        back_populates="incident", order_by="IncidentEvent.seq"
    )

    __mapper_args__ = {"version_id_col": version}  # noqa: RUF012 (optimistic locking)
    __table_args__ = (
        # At most one *active* incident per grouping key.
        Index(
            "uq_incidents_active_dedupe_key",
            "dedupe_key",
            unique=True,
            postgresql_where=text("status NOT IN ('resolved', 'closed')"),
        ),
        Index("ix_incidents_status_opened_at", "status", "opened_at"),
        CheckConstraint(
            "status IN ('open','acknowledged','investigating','remediating',"
            "'verifying','resolved','closed')",
            name="status",
        ),
        CheckConstraint("severity IN ('info','warning','critical')", name="severity"),
    )

    @property
    def short_id(self) -> str:
        return f"INC-{self.number:04d}"


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = _pk()
    fingerprint: Mapped[str] = mapped_column(String(32))
    starts_at: Mapped[datetime]
    status: Mapped[str] = mapped_column(String(10))
    alertname: Mapped[str] = mapped_column(String(64))
    service: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(10))
    summary: Mapped[str] = mapped_column(String(300))
    labels: Mapped[Json]
    annotations: Mapped[Json]
    generator_url: Mapped[str] = mapped_column(Text)
    ends_at: Mapped[datetime | None]
    first_received_at: Mapped[datetime]
    last_received_at: Mapped[datetime]
    receive_count: Mapped[int] = mapped_column(Integer, server_default=text("1"))
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="RESTRICT"), index=True
    )
    incident: Mapped[Incident | None] = relationship(back_populates="alerts")

    __table_args__ = (UniqueConstraint("fingerprint", "starts_at", name="uq_alerts_identity"),)


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    id: Mapped[uuid.UUID] = mapped_column(unique=True, default=uuid7)
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="RESTRICT"), index=True
    )
    at: Mapped[datetime]
    kind: Mapped[str] = mapped_column(String(50))
    actor: Mapped[str] = mapped_column(String(80))
    summary: Mapped[str] = mapped_column(String(500))
    data: Mapped[Json] = mapped_column(server_default=text("'{}'::jsonb"))
    correlation_id: Mapped[str | None] = mapped_column(String(64))

    incident: Mapped[Incident] = relationship(back_populates="events")


class Deployment(Base):
    __tablename__ = "deployments"

    id: Mapped[uuid.UUID] = _pk()
    service: Mapped[str] = mapped_column(String(64))
    environment: Mapped[str] = mapped_column(String(64))
    version: Mapped[str] = mapped_column(String(64))
    config_revision: Mapped[str | None] = mapped_column(String(32))
    previous_version: Mapped[str | None] = mapped_column(String(64))
    previous_config_revision: Mapped[str | None] = mapped_column(String(32))
    deployed_at: Mapped[datetime]
    deployed_by: Mapped[str] = mapped_column(String(120))
    source: Mapped[str] = mapped_column(String(32))
    change_ref: Mapped[str | None] = mapped_column(String(120))
    recorded_at: Mapped[datetime]

    __table_args__ = (
        UniqueConstraint(
            "service",
            "version",
            "config_revision",
            "deployed_at",
            name="uq_deployments_identity",
            postgresql_nulls_not_distinct=True,
        ),
        Index("ix_deployments_service_deployed_at", "service", "deployed_at"),
    )


class Principal(Base):
    __tablename__ = "principals"

    id: Mapped[uuid.UUID] = _pk()
    name: Mapped[str] = mapped_column(String(80), unique=True)
    role: Mapped[str] = mapped_column(String(20))
    token_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    active: Mapped[bool] = mapped_column(server_default=text("true"))
    created_at: Mapped[datetime]

    __table_args__ = (
        CheckConstraint("role IN ('viewer','responder','approver','admin')", name="role"),
    )


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = _pk()
    kind: Mapped[str] = mapped_column(String(64))
    payload: Mapped[Json]
    status: Mapped[str] = mapped_column(String(10), server_default=text("'pending'"))
    dedupe_key: Mapped[str | None] = mapped_column(String(200))
    attempts: Mapped[int] = mapped_column(Integer, server_default=text("0"))
    max_attempts: Mapped[int] = mapped_column(Integer, server_default=text("3"))
    run_after: Mapped[datetime]
    locked_by: Mapped[str | None] = mapped_column(String(80))
    locked_at: Mapped[datetime | None]
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime]
    finished_at: Mapped[datetime | None]

    __table_args__ = (
        Index("ix_jobs_claim", "status", "run_after"),
        # A job with a dedupe key can only be queued/running once at a time.
        Index(
            "uq_jobs_active_dedupe_key",
            "dedupe_key",
            unique=True,
            postgresql_where=text("status IN ('pending', 'running')"),
        ),
        CheckConstraint("status IN ('pending','running','done','failed')", name="status"),
    )


class AuditEvent(Base):
    """Append-only, hash-chained. UPDATE/DELETE are blocked by a trigger (migration 0001)."""

    __tablename__ = "audit_events"

    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    id: Mapped[uuid.UUID] = mapped_column(unique=True, default=uuid7)
    at: Mapped[datetime]
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(64))
    subject_type: Mapped[str] = mapped_column(String(32))
    subject_id: Mapped[str] = mapped_column(String(64))
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    data: Mapped[Json]
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)

    __table_args__ = (Index("ix_audit_events_subject", "subject_type", "subject_id"),)


class EvidenceCollection(Base):
    """One evidence-gathering run for an incident (refreshes create new collections)."""

    __tablename__ = "evidence_collections"

    id: Mapped[uuid.UUID] = _pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="RESTRICT"), index=True
    )
    status: Mapped[str] = mapped_column(String(10))  # complete | partial | failed
    window_start: Mapped[datetime]
    window_end: Mapped[datetime]
    onset: Mapped[datetime]
    errors: Mapped[Json]
    started_at: Mapped[datetime]
    finished_at: Mapped[datetime]
    trigger: Mapped[str] = mapped_column(String(80))

    items: Mapped[list[EvidenceItem]] = relationship(
        back_populates="collection", order_by="EvidenceItem.position"
    )

    __table_args__ = (CheckConstraint("status IN ('complete','partial','failed')", name="status"),)


class EvidenceItem(Base):
    """An observation (metric/log/change), derived signal, or data gap. Never AI output."""

    __tablename__ = "evidence_items"

    id: Mapped[uuid.UUID] = _pk()
    collection_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence_collections.id", ondelete="RESTRICT"), index=True
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="RESTRICT"), index=True
    )
    position: Mapped[int] = mapped_column(Integer)
    ref: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(10))
    source: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(200))
    summary: Mapped[str] = mapped_column(Text)
    query: Mapped[str | None] = mapped_column(Text)
    data: Mapped[Json]
    flags: Mapped[list[str]] = mapped_column(ARRAY(String(40)))

    collection: Mapped[EvidenceCollection] = relationship(back_populates="items")

    __table_args__ = (
        UniqueConstraint("collection_id", "ref", name="uq_evidence_items_collection_ref"),
        CheckConstraint("kind IN ('metric','log','change','derived','gap')", name="kind"),
    )


class Investigation(Base):
    """One AI (or mock) investigation run. Its content is hypotheses, never observations."""

    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = _pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="RESTRICT"), index=True
    )
    collection_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence_collections.id", ondelete="RESTRICT")
    )
    status: Mapped[str] = mapped_column(String(10))  # running | succeeded | failed
    provider: Mapped[str] = mapped_column(String(20))
    model: Mapped[str] = mapped_column(String(80))
    is_mock: Mapped[bool]
    prompt_version: Mapped[str] = mapped_column(String(40))
    input_hash: Mapped[str | None] = mapped_column(String(64))
    requested_by: Mapped[str] = mapped_column(String(120))
    started_at: Mapped[datetime]
    finished_at: Mapped[datetime | None]
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    report: Mapped[Json | None]
    validation: Mapped[Json | None]

    hypotheses: Mapped[list[HypothesisRow]] = relationship(
        back_populates="investigation", order_by="HypothesisRow.rank"
    )

    __table_args__ = (CheckConstraint("status IN ('running','succeeded','failed')", name="status"),)


class HypothesisRow(Base):
    """An AI-generated hypothesis. `generated` is always true and exists for explicitness."""

    __tablename__ = "hypotheses"

    id: Mapped[uuid.UUID] = _pk()
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigations.id", ondelete="RESTRICT"), index=True
    )
    rank: Mapped[int] = mapped_column(Integer)  # 0 = suspected root cause
    statement: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float]
    cited_evidence: Mapped[list[str]] = mapped_column(ARRAY(String(64)))
    why_less_likely: Mapped[str | None] = mapped_column(Text)
    uncited: Mapped[bool] = mapped_column(server_default=text("false"))
    generated: Mapped[bool] = mapped_column(server_default=text("true"))

    investigation: Mapped[Investigation] = relationship(back_populates="hypotheses")

    __table_args__ = (
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence"),
        CheckConstraint("generated", name="generated"),
    )


class ActionRequest(Base):
    """A proposed remediation. Only ever instantiated from the runbook catalogue.

    `idempotency_key` = sha256(runbook_id + sorted(parameters) + incident_id) and is
    unique among active requests, so the same proposal (by any source) is reused rather
    than duplicated. `params_sha256` / `runbook_sha256` are checked again at approval
    time: if the runbook file changed since the proposal, approval is refused (replay
    protection) and a fresh proposal is required.
    """

    __tablename__ = "action_requests"

    id: Mapped[uuid.UUID] = _pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="RESTRICT"), index=True
    )
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("investigations.id", ondelete="RESTRICT")
    )
    runbook_id: Mapped[str] = mapped_column(String(64))
    runbook_version: Mapped[int] = mapped_column(Integer)
    runbook_sha256: Mapped[str] = mapped_column(String(64))
    action_type: Mapped[str] = mapped_column(String(20))  # restart | rollback | scale
    parameters: Mapped[Json]
    params_sha256: Mapped[str] = mapped_column(String(64))
    idempotency_key: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(20))
    source: Mapped[str] = mapped_column(String(20))  # ai_recommendation | human | policy
    rationale: Mapped[str] = mapped_column(Text, server_default=text("''"))
    cited_evidence: Mapped[list[str]] = mapped_column(ARRAY(String(64)))
    requested_by: Mapped[str] = mapped_column(String(120))
    dry_run: Mapped[bool]
    created_at: Mapped[datetime]
    updated_at: Mapped[datetime]
    expires_at: Mapped[datetime]

    approvals: Mapped[list[Approval]] = relationship(
        back_populates="action_request", order_by="Approval.decided_at"
    )
    executions: Mapped[list[ActionExecution]] = relationship(
        back_populates="action_request", order_by="ActionExecution.attempt"
    )
    verifications: Mapped[list[Verification]] = relationship(
        back_populates="action_request", order_by="Verification.started_at"
    )

    __table_args__ = (
        Index(
            "uq_action_requests_active_idempotency_key",
            "idempotency_key",
            unique=True,
            postgresql_where=text(
                "status IN ('proposed','pending_approval','approved','executing','verifying')"
            ),
        ),
        Index("ix_action_requests_incident_id", "incident_id"),
        CheckConstraint(
            "status IN ('proposed','pending_approval','approved','executing','verifying',"
            "'succeeded','rejected','expired','failed','verification_failed','cancelled')",
            name="status",
        ),
        CheckConstraint("action_type IN ('restart','rollback','scale')", name="action_type"),
    )


class Approval(Base):
    """One approve/reject decision. Binds the exact parameters and runbook content."""

    __tablename__ = "approvals"

    id: Mapped[uuid.UUID] = _pk()
    action_request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("action_requests.id", ondelete="RESTRICT"), index=True
    )
    principal: Mapped[str] = mapped_column(String(120))
    decision: Mapped[str] = mapped_column(String(10))
    reason: Mapped[str | None] = mapped_column(Text)
    params_sha256: Mapped[str] = mapped_column(String(64))
    runbook_sha256: Mapped[str] = mapped_column(String(64))
    decided_at: Mapped[datetime]

    action_request: Mapped[ActionRequest] = relationship(back_populates="approvals")

    __table_args__ = (CheckConstraint("decision IN ('approved','rejected')", name="decision"),)


class ActionExecution(Base):
    """One execution attempt against the actuator. One row per bounded retry."""

    __tablename__ = "action_executions"

    id: Mapped[uuid.UUID] = _pk()
    action_request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("action_requests.id", ondelete="RESTRICT"), index=True
    )
    attempt: Mapped[int] = mapped_column(Integer)
    started_at: Mapped[datetime]
    finished_at: Mapped[datetime | None]
    outcome: Mapped[str] = mapped_column(String(20))  # changed | noop | error
    actuator_response: Mapped[Json | None]
    error: Mapped[str | None] = mapped_column(Text)

    action_request: Mapped[ActionRequest] = relationship(back_populates="executions")

    __table_args__ = (
        UniqueConstraint("action_request_id", "attempt", name="uq_action_executions_attempt"),
        CheckConstraint("outcome IN ('changed','noop','error')", name="outcome"),
    )


class Verification(Base):
    """Recovery verification for one action. `passed` is only ever set from measured samples."""

    __tablename__ = "verifications"

    id: Mapped[uuid.UUID] = _pk()
    action_request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("action_requests.id", ondelete="RESTRICT"), index=True
    )
    criteria: Mapped[Json]
    samples: Mapped[list[Any]] = mapped_column(JSONB)  # one entry per sampling tick
    passed: Mapped[bool | None]
    started_at: Mapped[datetime]
    finished_at: Mapped[datetime | None]

    action_request: Mapped[ActionRequest] = relationship(back_populates="verifications")


class Postmortem(Base):
    """One incident's postmortem. Regenerating a draft replaces its content in place
    (unlike evidence/investigations, there is deliberately only ever one row per
    incident — a postmortem is a living document, not a sequence of immutable runs).
    `generated_sections` names which top-level sections were last machine-written
    (from the timeline/evidence/investigation/actions) versus human-authored, so the
    UI can show "regenerating this will overwrite your edits" accurately.
    """

    __tablename__ = "postmortems"

    id: Mapped[uuid.UUID] = _pk()
    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="RESTRICT"), unique=True
    )
    status: Mapped[str] = mapped_column(String(10), server_default=text("'draft'"))
    markdown: Mapped[str] = mapped_column(Text)
    generated_sections: Mapped[list[str]] = mapped_column(ARRAY(String(40)))
    authored_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime]
    updated_at: Mapped[datetime]
    finalized_at: Mapped[datetime | None]
    finalized_by: Mapped[str | None] = mapped_column(String(120))

    __table_args__ = (CheckConstraint("status IN ('draft','final')", name="status"),)
