from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr

from actuator.catalog import ReleaseCatalog
from actuator.fleet import DeploymentEvent, FleetManager
from actuator.testing import FakeRuntime

REPO = Path(__file__).resolve().parents[3]
CATALOG_PATH = REPO / "deploy" / "actuator" / "releases.yaml"


@pytest.fixture
def catalog() -> ReleaseCatalog:
    return ReleaseCatalog.load(CATALOG_PATH)


@pytest.fixture
def runtime() -> FakeRuntime:
    return FakeRuntime()


@pytest.fixture
def events() -> list[DeploymentEvent]:
    return []


@pytest.fixture
def fleet(
    catalog: ReleaseCatalog, runtime: FakeRuntime, events: list[DeploymentEvent]
) -> FleetManager:
    async def sink(e: DeploymentEvent) -> None:
        events.append(e)

    return FleetManager(
        catalog,
        runtime,
        "sentinel-app",
        SecretStr("chaos"),
        event_sink=sink,
        clock=lambda: "2026-10-09T10:00:00+00:00",
    )
