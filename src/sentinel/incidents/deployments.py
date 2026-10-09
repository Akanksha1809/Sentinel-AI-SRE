"""Deployment (change) history, used to correlate changes with incident onset."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.audit import AuditLog
from sentinel.ids import Clock, uuid7
from sentinel.persistence.models import Deployment

_NAME = r"^[a-z0-9][a-z0-9-]{0,63}$"
_VERSION = r"^[0-9A-Za-z.+-]{1,64}$"


class DeploymentIn(BaseModel):
    """Deployment event (matches the actuator's DeploymentEvent wire format)."""

    model_config = ConfigDict(extra="ignore")

    service: str = Field(pattern=_NAME)
    environment: str | None = Field(default=None, pattern=_NAME)
    version: str = Field(pattern=_VERSION)
    config_revision: str | None = Field(default=None, pattern=r"^[0-9A-Za-z.-]{1,32}$")
    previous_version: str | None = Field(default=None, pattern=_VERSION)
    previous_config_revision: str | None = Field(default=None, pattern=r"^[0-9A-Za-z.-]{1,32}$")
    deployed_at: datetime
    deployed_by: str = Field(min_length=1, max_length=120)
    source: str = Field(default="api", pattern=r"^[a-z_]{1,32}$")
    change_ref: str | None = Field(default=None, max_length=120)


class DeploymentService:
    def __init__(self, clock: Clock, audit: AuditLog, environment: str) -> None:
        self._clock = clock
        self._audit = audit
        self._environment = environment

    async def record(
        self, session: AsyncSession, dep: DeploymentIn, actor: str
    ) -> tuple[Deployment, bool]:
        """Idempotent on (service, version, config_revision, deployed_at).

        Returns (row, created).
        """
        values = dep.model_dump()
        values["environment"] = dep.environment or self._environment
        stmt = (
            insert(Deployment)
            .values(id=uuid7(), recorded_at=self._clock.now(), **values)
            .on_conflict_do_nothing(constraint="uq_deployments_identity")
            .returning(Deployment.id)
        )
        new_id = (await session.execute(stmt)).scalar_one_or_none()
        if new_id is not None:
            row = (
                await session.execute(select(Deployment).where(Deployment.id == new_id))
            ).scalar_one()
            await self._audit.append(
                session,
                actor=actor,
                action="deployment.recorded",
                subject_type="deployment",
                subject_id=row.id,
                data={
                    "service": row.service,
                    "version": row.version,
                    "config_revision": row.config_revision,
                    "previous_version": row.previous_version,
                },
            )
            return row, True
        existing = (
            await session.execute(
                select(Deployment).where(
                    Deployment.service == dep.service,
                    Deployment.version == dep.version,
                    Deployment.config_revision.is_not_distinct_from(dep.config_revision),
                    Deployment.deployed_at == dep.deployed_at,
                )
            )
        ).scalar_one()
        return existing, False

    async def list(
        self, session: AsyncSession, service: str | None, since: datetime | None, limit: int
    ) -> list[Deployment]:
        stmt = select(Deployment).order_by(Deployment.deployed_at.desc()).limit(limit)
        if service:
            stmt = stmt.where(Deployment.service == service)
        if since:
            stmt = stmt.where(Deployment.deployed_at >= since)
        return list((await session.execute(stmt)).scalars())
