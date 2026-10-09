"""Dependency injection: everything Sentinel needs, built once from Settings.

Tests construct a Container with fakes (clock, settings) and a test database engine.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from sentinel.audit import AuditLog
from sentinel.config import Settings
from sentinel.ids import Clock, SystemClock
from sentinel.incidents.deployments import DeploymentService
from sentinel.incidents.service import IncidentService
from sentinel.jobs.queue import JobQueue
from sentinel.observability.metrics import Metrics
from sentinel.persistence.db import make_engine, make_sessionmaker, migration_head


@dataclass
class Container:
    settings: Settings
    clock: Clock
    engine: AsyncEngine
    sessions: async_sessionmaker[AsyncSession]
    metrics: Metrics
    audit: AuditLog
    incidents: IncidentService
    deployments: DeploymentService
    jobs: JobQueue
    expected_migration: str | None = None

    @classmethod
    def build(
        cls, settings: Settings, *, clock: Clock | None = None, engine: AsyncEngine | None = None
    ) -> Container:
        clock = clock or SystemClock()
        engine = engine or make_engine(settings.database_url(), settings.db_pool_size)
        audit = AuditLog(clock)
        return cls(
            settings=settings,
            clock=clock,
            engine=engine,
            sessions=make_sessionmaker(engine),
            metrics=Metrics(),
            audit=audit,
            incidents=IncidentService(clock, audit, settings.reopen_window),
            deployments=DeploymentService(clock, audit, settings.environment),
            jobs=JobQueue(clock),
            expected_migration=migration_head(),
        )
