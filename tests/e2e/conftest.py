"""Fixtures for e2e tests: drive the real, already-running Compose stack
(`make up`) through the same `SentinelDemoClient` the `sentinel-demo` CLI uses —
see `src/sentinel/demo/`. Needs `SENTINEL_EXECUTION_MODE=live` on sentinel-worker
(`make e2e-up`); in `dry_run` (the safe default) remediation is a deliberate no-op,
so recovery correctly never verifies and these tests fail loudly with a
`DemoStalledError` rather than passing on a fleet that was never actually fixed.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from sentinel.demo.client import DemoConfig, SentinelDemoClient

SENTINEL_URL = "http://127.0.0.1:8080"
ACTUATOR_URL = "http://127.0.0.1:8085"


@pytest.fixture
async def demo() -> AsyncIterator[SentinelDemoClient]:
    config = DemoConfig.from_secrets(
        Path("secrets"), sentinel_url=SENTINEL_URL, actuator_url=ACTUATOR_URL
    )
    async with SentinelDemoClient(config) as client:
        if not await client.sentinel_ready():
            pytest.fail(
                f"sentinel-api not ready at {SENTINEL_URL} — is the stack up? (`make e2e-up`)"
            )
        yield client
