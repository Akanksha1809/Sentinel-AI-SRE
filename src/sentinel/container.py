"""Dependency injection: everything Sentinel needs, built once from Settings.

Tests construct a Container with fakes (clock, settings) and a test database engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from sentinel.audit import AuditLog
from sentinel.config import Settings
from sentinel.ids import Clock, SystemClock
from sentinel.incidents.deployments import DeploymentService
from sentinel.incidents.service import IncidentService
from sentinel.jobs.queue import JobQueue
from sentinel.observability.metrics import Metrics
from sentinel.persistence.db import make_engine, make_sessionmaker, migration_head
from sentinel.remediation.policy import PolicyEngine
from sentinel.remediation.runbooks import RunbookCatalog
from sentinel.remediation.service import ActionService
from sentinel.reports.service import PostmortemService


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
    catalog: RunbookCatalog
    actions: ActionService
    postmortems: PostmortemService
    expected_migration: str | None = None

    @classmethod
    def build(
        cls, settings: Settings, *, clock: Clock | None = None, engine: AsyncEngine | None = None
    ) -> Container:
        clock = clock or SystemClock()
        engine = engine or make_engine(settings.database_url(), settings.db_pool_size)
        audit = AuditLog(clock)
        jobs = JobQueue(clock)
        incidents = IncidentService(
            clock,
            audit,
            settings.reopen_window,
            jobs,
            timedelta(seconds=settings.evidence_delay_s),
        )
        catalog = RunbookCatalog.load(settings.runbooks_dir)
        policy = PolicyEngine(
            max_per_incident=settings.action_max_per_incident, cooldown=settings.action_cooldown
        )
        metrics = Metrics()
        return cls(
            settings=settings,
            clock=clock,
            engine=engine,
            sessions=make_sessionmaker(engine),
            metrics=metrics,
            audit=audit,
            incidents=incidents,
            deployments=DeploymentService(clock, audit, settings.environment),
            jobs=jobs,
            catalog=catalog,
            actions=ActionService(
                clock,
                audit,
                incidents,
                catalog,
                jobs,
                policy,
                expiry=settings.action_expiry,
                dry_run_default=settings.dry_run_default,
                metrics=metrics,
            ),
            postmortems=PostmortemService(clock, audit, incidents),
            expected_migration=migration_head(),
        )
