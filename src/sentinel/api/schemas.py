"""API response/request models (the public contract; see docs/api-contracts.md)."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any
from urllib.parse import quote, urlencode

from pydantic import BaseModel, Field

from sentinel.config import Settings
from sentinel.persistence.models import Alert, Deployment, Incident, IncidentEvent


class AlertOut(BaseModel):
    id: uuid.UUID
    fingerprint: str
    alertname: str
    status: str
    severity: str
    summary: str
    starts_at: datetime
    ends_at: datetime | None
    receive_count: int
    labels: dict[str, Any]
    annotations: dict[str, Any]

    @classmethod
    def of(cls, a: Alert) -> AlertOut:
        return cls(
            id=a.id,
            fingerprint=a.fingerprint,
            alertname=a.alertname,
            status=a.status,
            severity=a.severity,
            summary=a.summary,
            starts_at=a.starts_at,
            ends_at=a.ends_at,
            receive_count=a.receive_count,
            labels=a.labels,
            annotations=a.annotations,
        )


class EventOut(BaseModel):
    at: datetime
    kind: str
    actor: str
    summary: str
    data: dict[str, Any]

    @classmethod
    def of(cls, e: IncidentEvent) -> EventOut:
        return cls(at=e.at, kind=e.kind, actor=e.actor, summary=e.summary, data=e.data)


class IncidentSummary(BaseModel):
    id: uuid.UUID
    short_id: str
    title: str
    service: str
    environment: str
    status: str
    severity: str
    opened_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    resolved_verified: bool
    updated_at: datetime

    @classmethod
    def of(cls, i: Incident) -> IncidentSummary:
        return cls(
            id=i.id,
            short_id=i.short_id,
            title=i.title,
            service=i.service,
            environment=i.environment,
            status=i.status,
            severity=i.severity,
            opened_at=i.opened_at,
            acknowledged_at=i.acknowledged_at,
            resolved_at=i.resolved_at,
            resolved_verified=i.resolved_verified,
            updated_at=i.updated_at,
        )


class TelemetryLinks(BaseModel):
    grafana_dashboard: str
    prometheus_graph: str
    loki_explore: str


def telemetry_links(i: Incident, s: Settings, now: datetime) -> TelemetryLinks:
    start = int(i.opened_at.timestamp() * 1000) - 15 * 60_000
    end = int((i.resolved_at or now).timestamp() * 1000) + 5 * 60_000
    svc = i.service
    grafana = f"{s.grafana_url}/d/sentinel-{quote(svc)}?" + urlencode(
        {"var-service": svc, "from": start, "to": end}
    )
    prom = f"{s.prometheus_url}/graph?" + urlencode(
        {
            "g0.expr": f'service:http_error_ratio:rate30s{{service="{svc}"}}',
            "g0.range_input": "1h",
            "g0.end_input": datetime.fromtimestamp(end / 1000).isoformat(),
        }
    )
    loki_state = {
        "datasource": "loki",
        "queries": [{"refId": "A", "expr": f'{{service="{svc}"}} | json'}],
        "range": {"from": str(start), "to": str(end)},
    }
    loki_query = json.dumps(loki_state, separators=(",", ":"))
    loki = f"{s.grafana_url}/explore?" + urlencode({"left": loki_query})
    return TelemetryLinks(grafana_dashboard=grafana, prometheus_graph=prom, loki_explore=loki)


class IncidentDetail(IncidentSummary):
    resolution: str | None
    alerts: list[AlertOut]
    timeline: list[EventOut]
    links: TelemetryLinks


class IncidentPage(BaseModel):
    items: list[IncidentSummary]
    next_cursor: int | None


class NoteIn(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


class AckIn(BaseModel):
    note: str | None = Field(default=None, max_length=1000)


class ResolveIn(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)


class WebhookIncident(BaseModel):
    id: uuid.UUID
    short_id: str
    outcome: str


class WebhookAccepted(BaseModel):
    received: int
    new: int
    updated: int
    incidents: list[WebhookIncident]


class DeploymentOut(BaseModel):
    id: uuid.UUID
    service: str
    environment: str
    version: str
    config_revision: str | None
    previous_version: str | None
    previous_config_revision: str | None
    deployed_at: datetime
    deployed_by: str
    source: str
    change_ref: str | None

    @classmethod
    def of(cls, d: Deployment) -> DeploymentOut:
        return cls(
            id=d.id,
            service=d.service,
            environment=d.environment,
            version=d.version,
            config_revision=d.config_revision,
            previous_version=d.previous_version,
            previous_config_revision=d.previous_config_revision,
            deployed_at=d.deployed_at,
            deployed_by=d.deployed_by,
            source=d.source,
            change_ref=d.change_ref,
        )


class AuditOut(BaseModel):
    seq: int
    at: datetime
    actor: str
    action: str
    subject_type: str
    subject_id: str
    correlation_id: str | None
    data: dict[str, Any]
    hash: str
