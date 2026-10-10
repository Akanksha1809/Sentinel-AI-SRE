from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str | None) -> Severity:
        """Unknown or missing severities from alert labels map to WARNING (never dropped)."""
        try:
            return cls((value or "").strip().lower())
        except ValueError:
            return cls.WARNING

    @staticmethod
    def max(a: Severity, b: Severity) -> Severity:
        return a if a.rank >= b.rank else b


_SEVERITY_RANK = {Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}


class AlertStatus(StrEnum):
    FIRING = "firing"
    RESOLVED = "resolved"


class IncidentStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    REMEDIATING = "remediating"
    VERIFYING = "verifying"
    RESOLVED = "resolved"
    CLOSED = "closed"

    @property
    def is_active(self) -> bool:
        return self not in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED)


class Role(StrEnum):
    VIEWER = "viewer"
    RESPONDER = "responder"
    APPROVER = "approver"
    ADMIN = "admin"

    def satisfies(self, required: Role) -> bool:
        return _ROLE_RANK[self] >= _ROLE_RANK[required]


_ROLE_RANK = {Role.VIEWER: 0, Role.RESPONDER: 1, Role.APPROVER: 2, Role.ADMIN: 3}


class EventKind(StrEnum):
    INCIDENT_OPENED = "incident.opened"
    INCIDENT_REOPENED = "incident.reopened"
    INCIDENT_STATUS_CHANGED = "incident.status_changed"
    INCIDENT_SEVERITY_CHANGED = "incident.severity_changed"
    ALERT_ATTACHED = "alert.attached"
    ALERT_RESOLVED = "alert.resolved"
    ALERT_REFIRED = "alert.refired"
    ALL_ALERTS_RESOLVED = "incident.all_alerts_resolved"
    NOTE_ADDED = "note.added"
    EVIDENCE_REQUESTED = "evidence.requested"
    EVIDENCE_COLLECTED = "evidence.collected"
    INVESTIGATION_REQUESTED = "investigation.requested"
    INVESTIGATION_COMPLETED = "investigation.completed"
    INVESTIGATION_FAILED = "investigation.failed"
    ACTION_PROPOSED = "action.proposed"
    ACTION_APPROVED = "action.approved"
    ACTION_REJECTED = "action.rejected"
    ACTION_EXPIRED = "action.expired"
    ACTION_EXECUTING = "action.executing"
    ACTION_EXECUTED = "action.executed"
    ACTION_EXECUTION_FAILED = "action.execution_failed"
    ACTION_VERIFYING = "action.verifying"
    ACTION_VERIFIED = "action.verified"
    ACTION_VERIFICATION_FAILED = "action.verification_failed"
    POSTMORTEM_GENERATED = "postmortem.generated"
    POSTMORTEM_EDITED = "postmortem.edited"
    POSTMORTEM_FINALIZED = "postmortem.finalized"


class ActionStatus(StrEnum):
    """Lifecycle of one proposed remediation. See domain/actions.py for transitions."""

    PROPOSED = "proposed"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    SUCCEEDED = "succeeded"
    REJECTED = "rejected"
    EXPIRED = "expired"
    FAILED = "failed"
    VERIFICATION_FAILED = "verification_failed"
    CANCELLED = "cancelled"

    @property
    def is_active(self) -> bool:
        return self in (
            ActionStatus.PROPOSED,
            ActionStatus.PENDING_APPROVAL,
            ActionStatus.APPROVED,
            ActionStatus.EXECUTING,
            ActionStatus.VERIFYING,
        )


class ApprovalDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


class ExecutionMode(StrEnum):
    """Global safety switch. `dry_run` is the default; `live` is an explicit opt-in."""

    DRY_RUN = "dry_run"
    LIVE = "live"
