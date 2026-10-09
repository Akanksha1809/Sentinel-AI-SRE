"""Alertmanager webhook ingestion.

Status codes are chosen for Alertmanager's retry semantics: it retries on 5xx and
gives up on 4xx. Malformed or unauthorised payloads get 4xx (retrying won't help);
database or internal failures get 5xx so the notification is redelivered. Ingestion is
idempotent, so redelivery is safe.
"""

from __future__ import annotations

import json
import uuid
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy import select

from sentinel.api.deps import ContainerDep, require_webhook_token
from sentinel.api.schemas import WebhookAccepted, WebhookIncident
from sentinel.domain.enums import AlertStatus
from sentinel.ingestion.alertmanager import AMWebhook, normalize
from sentinel.persistence.models import Incident

router = APIRouter(prefix="/api/v1/webhooks", tags=["ingestion"])
log = structlog.get_logger("sentinel.ingestion")


async def _read_capped(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(413, f"payload exceeds {limit} bytes")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:  # also covers chunked bodies without Content-Length
            raise HTTPException(413, f"payload exceeds {limit} bytes")
    return bytes(body)


@router.post("/alertmanager", status_code=202, response_model=WebhookAccepted)
async def alertmanager_webhook(
    request: Request,
    container: ContainerDep,
    actor: Annotated[str, Depends(require_webhook_token)],
) -> WebhookAccepted:
    m = container.metrics
    try:
        raw = await _read_capped(request, container.settings.webhook_max_bytes)
    except HTTPException:
        m.webhook_rejected.labels("too_large").inc()
        raise
    try:
        payload = AMWebhook.model_validate(json.loads(raw))
    except (ValueError, ValidationError) as exc:
        m.webhook_rejected.labels("invalid").inc()
        detail = exc.errors()[0]["msg"] if isinstance(exc, ValidationError) else "invalid JSON"
        raise HTTPException(422, f"invalid Alertmanager payload: {detail}") from exc

    alerts = normalize(payload, container.settings.environment)
    async with container.sessions.begin() as session:
        result = await container.incidents.ingest(session, alerts, actor=actor)
        numbers: dict[uuid.UUID, int] = {}
        if result.incidents:
            rows = await session.execute(
                select(Incident.id, Incident.number).where(Incident.id.in_(result.incidents))
            )
            numbers = {incident_id: number for incident_id, number in rows}

    for a in alerts:
        m.alerts_received.labels(a.status.value).inc()
    for outcome in result.incidents.values():
        m.incidents.labels(outcome).inc()
    log.info(
        "alerts ingested",
        received=result.received,
        new=result.new_alerts,
        firing=sum(a.status is AlertStatus.FIRING for a in alerts),
        incidents={str(k): v for k, v in result.incidents.items()},
        group_key=payload.groupKey[:200],
    )
    return WebhookAccepted(
        received=result.received,
        new=result.new_alerts,
        updated=result.updated_alerts,
        incidents=[
            WebhookIncident(id=iid, short_id=f"INC-{numbers[iid]:04d}", outcome=outcome)
            for iid, outcome in result.incidents.items()
        ],
    )
