"""Deployments, audit, and health endpoints."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import select, text

from sentinel.api.deps import Admin, Approver, ContainerDep, Viewer, require_deployer
from sentinel.api.schemas import AuditOut, DeploymentOut
from sentinel.audit import verify_chain
from sentinel.incidents.deployments import DeploymentIn
from sentinel.persistence.models import AuditEvent

deployments = APIRouter(prefix="/api/v1/deployments", tags=["deployments"])
audit = APIRouter(prefix="/api/v1/audit", tags=["audit"])
health = APIRouter(tags=["health"])


@deployments.post("", status_code=201, response_model=DeploymentOut)
async def record_deployment(
    body: DeploymentIn,
    response: Response,
    container: ContainerDep,
    actor: Annotated[str, Depends(require_deployer)],
) -> DeploymentOut:
    async with container.sessions.begin() as session:
        row, created = await container.deployments.record(session, body, actor)
    container.metrics.deployments.labels(str(created).lower()).inc()
    if not created:
        response.status_code = 200  # idempotent replay
    return DeploymentOut.of(row)


@deployments.get("", response_model=list[DeploymentOut])
async def list_deployments(
    container: ContainerDep,
    _: Viewer,
    service: Annotated[str | None, Query(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")] = None,
    since: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[DeploymentOut]:
    async with container.sessions() as session:
        rows = await container.deployments.list(session, service, since, limit)
    return [DeploymentOut.of(d) for d in rows]


@audit.get("", response_model=list[AuditOut])
async def list_audit(
    container: ContainerDep,
    _: Approver,
    subject_id: Annotated[str | None, Query(max_length=64)] = None,
    since: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> list[AuditOut]:
    stmt = select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(limit)
    if subject_id:
        stmt = stmt.where(AuditEvent.subject_id == subject_id)
    if since:
        stmt = stmt.where(AuditEvent.at >= since)
    async with container.sessions() as session:
        rows = (await session.execute(stmt)).scalars().all()
    return [
        AuditOut(
            seq=e.seq,
            at=e.at,
            actor=e.actor,
            action=e.action,
            subject_type=e.subject_type,
            subject_id=e.subject_id,
            correlation_id=e.correlation_id,
            data=e.data,
            hash=e.hash,
        )
        for e in rows
    ]


@audit.get("/verify")
async def verify_audit(container: ContainerDep, _: Admin) -> dict[str, Any]:
    async with container.sessions() as session:
        result = await verify_chain(session)
    return {
        "ok": result.ok,
        "checked": result.checked,
        "first_bad_seq": result.first_bad_seq,
        "reason": result.reason,
    }


@health.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness: the process is serving. Dependencies are deliberately not checked."""
    return {"status": "ok"}


@health.get("/readyz")
async def readyz(container: ContainerDep) -> JSONResponse:
    checks: dict[str, Any] = {}
    ok = True
    start = time.perf_counter()
    try:
        async with container.sessions() as session:
            await session.execute(text("SELECT 1"))
            current = (
                await session.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar_one_or_none()
        expected = container.expected_migration
        migrated = expected is None or current == expected
        checks["database"] = {
            "ok": True,
            "latency_ms": round((time.perf_counter() - start) * 1000, 1),
        }
        checks["migrations"] = {"ok": migrated, "current": current, "expected": expected}
        ok = migrated
    except Exception as exc:
        checks["database"] = {"ok": False, "error": type(exc).__name__}
        ok = False
    return JSONResponse(
        {"status": "ready" if ok else "not_ready", "checks": checks}, status_code=200 if ok else 503
    )


@health.get("/metrics")
async def metrics(container: ContainerDep) -> Response:
    return Response(generate_latest(container.metrics.registry), media_type=CONTENT_TYPE_LATEST)
