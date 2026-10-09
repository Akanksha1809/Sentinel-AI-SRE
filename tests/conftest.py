"""Shared fixtures. Integration fixtures start a real Postgres 18 via testcontainers.

The database is prepared exactly like production: roles bootstrapped by
`bootstrap_roles` as the superuser, migrations applied as `sentinel_migrator`, and
the application connecting as the least-privilege `sentinel_app` role.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL

PG_IMAGE = "postgres:18.6"
RUNBOOKS_DIR = Path(__file__).resolve().parents[1] / "runbooks"
ADMIN_PW = "admin_test_password_123"
MIGRATOR_PW = "migrator_test_password_123"
APP_PW = "app_test_password_12345"
WEBHOOK_TOKEN = "webhook-test-token-0123456789"
DEPLOYER_TOKEN = "deployer-test-token-0123456789"
ADMIN_TOKEN = "snt_admin_test_token_0123456789"


def _configure_docker_for_testcontainers() -> None:
    """testcontainers reads DOCKER_HOST, not docker contexts (Colima, OrbStack, ...)."""
    if os.environ.get("DOCKER_HOST") or not shutil.which("docker"):
        return
    host = subprocess.run(
        ["docker", "context", "inspect", "-f", "{{.Endpoints.docker.Host}}"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    if host and host != "unix:///var/run/docker.sock":
        os.environ["DOCKER_HOST"] = host
        # Inside the VM the socket lives at the standard path (needed by Ryuk).
        os.environ.setdefault("TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE", "/var/run/docker.sock")


@dataclass(frozen=True)
class PgInfo:
    host: str
    port: int

    def url(self, user: str, password: str) -> str:
        return URL.create(
            "postgresql+psycopg",
            username=user,
            password=password,
            host=self.host,
            port=self.port,
            database="sentinel",
        ).render_as_string(hide_password=False)

    @property
    def admin_url(self) -> str:
        return self.url("sentinel_admin", ADMIN_PW)

    @property
    def app_url(self) -> str:
        return self.url("sentinel_app", APP_PW)


@pytest.fixture(scope="session")
def pg() -> Iterator[PgInfo]:
    _configure_docker_for_testcontainers()
    from testcontainers.community.postgres import PostgresContainer

    from sentinel.persistence.db import MIGRATOR_ROLE, bootstrap_roles, upgrade

    with PostgresContainer(
        PG_IMAGE, username="sentinel_admin", password=ADMIN_PW, dbname="sentinel", driver="psycopg"
    ) as container:
        info = PgInfo(container.get_container_host_ip(), int(container.get_exposed_port(5432)))
        engine = create_engine(info.admin_url, isolation_level="AUTOCOMMIT")
        with engine.connect() as conn:
            bootstrap_roles(conn, "sentinel", MIGRATOR_PW, APP_PW)
        engine.dispose()
        upgrade(info.url(MIGRATOR_ROLE, MIGRATOR_PW))
        yield info


_TABLES = (
    "hypotheses, investigations, evidence_items, evidence_collections, alerts, "
    "incident_events, incidents, deployments, principals, jobs, audit_events"
)


@pytest.fixture
def clean_db(pg: PgInfo) -> PgInfo:
    """Empty all tables. Uses the superuser with triggers suspended (audit is append-only)."""
    engine = create_engine(pg.admin_url, isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        conn.execute(text("SET session_replication_role = replica"))
        conn.execute(text(f"TRUNCATE {_TABLES} RESTART IDENTITY CASCADE"))
        conn.execute(text("ALTER SEQUENCE incident_number_seq RESTART WITH 1"))
    engine.dispose()
    return pg


@pytest.fixture
def clock() -> Any:
    from sentinel.ids import ManualClock

    return ManualClock()


@pytest.fixture
def settings(clean_db: PgInfo) -> Any:
    from sentinel.config import Settings

    return Settings(
        db_host=clean_db.host,
        db_port=clean_db.port,
        db_password=SecretStr(APP_PW),
        webhook_token=SecretStr(WEBHOOK_TOKEN),
        deployer_token=SecretStr(DEPLOYER_TOKEN),
        bootstrap_admin_token=SecretStr(ADMIN_TOKEN),
        reopen_window_s=600,
        runbooks_dir=RUNBOOKS_DIR,
    )


@pytest.fixture
async def container(settings: Any, clock: Any) -> AsyncIterator[Any]:
    from sentinel.container import Container

    c = Container.build(settings, clock=clock)
    yield c
    await c.engine.dispose()


@pytest.fixture
def am_alert() -> Callable[..., dict[str, Any]]:
    """Factory for Alertmanager v4 alert objects."""

    def make(
        alertname: str = "ShopApiHighErrorBurnRate",
        *,
        service: str = "shop-api",
        severity: str = "critical",
        status: str = "firing",
        fingerprint: str | None = None,
        starts_at: datetime | None = None,
        summary: str | None = None,
        **labels: str,
    ) -> dict[str, Any]:
        start = starts_at or datetime.fromisoformat("2026-10-09T11:23:42+00:00")
        return {
            "status": status,
            "labels": {
                "alertname": alertname,
                "service": service,
                "severity": severity,
                "environment": "local",
                **labels,
            },
            "annotations": {"summary": summary or f"{service}: {alertname}"},
            "startsAt": start.isoformat(),
            "endsAt": (start + timedelta(minutes=5)).isoformat()
            if status == "resolved"
            else "0001-01-01T00:00:00Z",
            "generatorURL": "http://prometheus:9090/graph",
            "fingerprint": fingerprint
            or hashlib.sha256(f"{alertname}|{service}".encode()).hexdigest()[:16],
        }

    return make


@pytest.fixture
def am_payload() -> Callable[..., dict[str, Any]]:
    def make(*alerts: dict[str, Any]) -> dict[str, Any]:
        status = "firing" if any(a["status"] == "firing" for a in alerts) else "resolved"
        return {
            "version": "4",
            "groupKey": "{}:{}",
            "status": status,
            "receiver": "sentinel",
            "truncatedAlerts": 0,
            "externalURL": "http://alertmanager:9093",
            "alerts": list(alerts),
        }

    return make
