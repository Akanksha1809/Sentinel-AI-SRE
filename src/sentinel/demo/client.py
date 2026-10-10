"""HTTP client for driving the real Sentinel stack end to end: inject a fault
through the actuator's demo-only endpoints (`POST /v1/deploy`, `POST
/v1/faults/{service}/chaos/{mode}` — both explicitly gated behind the fault token,
separate from the actuator's own remediation token), then poll the Sentinel API for
the incident to appear, get investigated, get an action proposed, optionally
approve it, and resolve. Every step is the same request a human or a real
Alertmanager delivery would make — nothing here reaches into the database directly.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

import httpx

T = TypeVar("T")


class DemoTimeoutError(TimeoutError):
    """A polling step didn't reach the expected state within its budget."""


class DemoStalledError(RuntimeError):
    """Remediation reached a terminal non-recovering state with nothing further
    queued (e.g. verification_failed) - a distinct, diagnosable outcome from "still
    in progress", most commonly because the stack is running in dry_run mode, so
    the fleet was never actually changed and recovery correctly never verifies."""


@dataclass(frozen=True)
class DemoConfig:
    sentinel_url: str = "http://127.0.0.1:8080"
    actuator_url: str = "http://127.0.0.1:8085"
    admin_token: str = ""
    fault_token: str = ""
    poll_interval_s: float = 2.0

    @classmethod
    def from_secrets(
        cls,
        secrets_dir: Path = Path("secrets"),
        *,
        sentinel_url: str = "http://127.0.0.1:8080",
        actuator_url: str = "http://127.0.0.1:8085",
    ) -> DemoConfig:
        def read(name: str) -> str:
            path = secrets_dir / name
            if not path.is_file():
                raise FileNotFoundError(
                    f"{path} not found — run `make secrets` (or `./scripts/gen-secrets.sh`) first"
                )
            return path.read_text(encoding="utf-8").strip()

        return cls(
            sentinel_url=sentinel_url,
            actuator_url=actuator_url,
            admin_token=read("sentinel_admin_token"),
            fault_token=read("fault_token"),
        )


class SentinelDemoClient:
    def __init__(self, config: DemoConfig) -> None:
        self._cfg = config
        self._sentinel = httpx.AsyncClient(
            base_url=config.sentinel_url,
            headers={"Authorization": f"Bearer {config.admin_token}"},
            # A live run on a loaded host (demo stack + whatever else is running)
            # saw an occasional plain GET take >10s under contention; 30s gives
            # real headroom without masking an actual hang during polling.
            timeout=30.0,
        )
        self._actuator = httpx.AsyncClient(
            base_url=config.actuator_url,
            headers={"Authorization": f"Bearer {config.fault_token}", "X-Actor": "sentinel-demo"},
            # Deploys replace containers and wait on health checks before responding;
            # a live run measured ~11s even for a two-replica rolling replace, so a
            # 10s client timeout was tripping while the actuator was still working.
            timeout=60.0,
        )

    async def __aenter__(self) -> SentinelDemoClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._sentinel.aclose()
        await self._actuator.aclose()

    async def sentinel_ready(self) -> bool:
        try:
            r = await self._sentinel.get("/readyz")
        except httpx.TransportError:
            return False
        return r.status_code == 200

    # ------------------------------------------------------------- triggers
    async def deploy(
        self, version: str, config_revision: str, change_ref: str, *, service: str = "shop-api"
    ) -> None:
        r = await self._actuator.post(
            "/v1/deploy",
            json={
                "service": service,
                "version": version,
                "config_revision": config_revision,
                "change_ref": change_ref,
            },
        )
        r.raise_for_status()

    async def inject_memory_chaos(
        self,
        *,
        service: str = "shop-api",
        rate_mb_s: float = 10.0,
        target_rss_mb: int = 220,
        duration_s: int = 300,
    ) -> None:
        """Default rate is deliberately aggressive (vs. the demo-app's own internal
        default of 2.0): a live run on a loaded host (traffic from loadgen, several
        other containers competing for CPU) measured the allocator's async ticks
        falling well behind the nominal rate, so a slow default risked the alert's
        `for: 30s` window never seeing a sustained breach within a reasonable demo
        timeout."""
        r = await self._actuator.post(
            f"/v1/faults/{service}/chaos/memory",
            json={"rate_mb_s": rate_mb_s, "target_rss_mb": target_rss_mb, "duration_s": duration_s},
        )
        r.raise_for_status()

    async def clear_chaos(self, service: str = "shop-api") -> None:
        """Best-effort baseline reset: there may be no chaos to clear, and a replica
        that was just replaced by a baseline deploy a moment earlier can be briefly
        unreachable, so a failure here is never fatal to a scenario run."""
        with suppress(httpx.HTTPError):
            await self._actuator.delete(f"/v1/faults/{service}/chaos")

    async def reset_active_incidents(self, service: str) -> list[str]:
        """Resolve + close any not-yet-closed incident for `service`. Deliberately
        *not* filtered to `active=True`: a `resolved` (but not `closed`) incident is
        still eligible to reopen a *new* alert within the reopen window (see
        `IncidentService._recently_resolved`, which matches on `status == resolved`
        alone), so leaving one behind would silently absorb the next scenario's
        alert into the old incident instead of a fresh, trackable one appearing."""
        page = await self._get("/api/v1/incidents", service=service, limit=50)
        closed = []
        for item in page["items"]:
            if item["status"] == "closed":
                continue
            ref = item["short_id"]
            if item["status"] != "resolved":
                await self._sentinel.post(
                    f"/api/v1/incidents/{ref}/resolve",
                    json={"reason": "sentinel-demo: reset before next scenario run"},
                )
            r = await self._sentinel.post(f"/api/v1/incidents/{ref}/close")
            if r.status_code == 200:
                closed.append(ref)
        return closed

    # ------------------------------------------------------------- reads
    async def _get(self, path: str, **params: Any) -> Any:
        r = await self._sentinel.get(path, params=params)
        r.raise_for_status()
        return r.json()

    async def latest_incident(
        self, service: str, *, opened_after: datetime
    ) -> dict[str, Any] | None:
        page = await self._get("/api/v1/incidents", service=service, limit=20)
        for item in page["items"]:  # newest first
            if datetime.fromisoformat(item["opened_at"]) >= opened_after:
                return dict(item)
        return None

    async def incident_detail(self, ref: str) -> dict[str, Any]:
        return dict(await self._get(f"/api/v1/incidents/{ref}"))

    async def actions_for(self, ref: str) -> list[dict[str, Any]]:
        return list(await self._get(f"/api/v1/incidents/{ref}/actions"))

    async def investigations_for(self, ref: str) -> list[dict[str, Any]]:
        return list(await self._get(f"/api/v1/incidents/{ref}/investigations"))

    async def approve(self, action_id: str, reason: str) -> dict[str, Any]:
        r = await self._sentinel.post(
            f"/api/v1/actions/{action_id}/approve", json={"reason": reason}
        )
        r.raise_for_status()
        return dict(r.json())

    # ------------------------------------------------------------- polling
    async def poll_until(
        self, label: str, timeout_s: float, check: Callable[[], Awaitable[T | None]]
    ) -> T:
        """Call `check` every `poll_interval_s` until it returns a truthy value, or
        raise `DemoTimeoutError` naming what was being waited for."""
        deadline = time.monotonic() + timeout_s
        while True:
            result = await check()
            if result:
                return result
            if time.monotonic() >= deadline:
                raise DemoTimeoutError(f"timed out after {timeout_s:.0f}s waiting for: {label}")
            await asyncio.sleep(self._cfg.poll_interval_s)

    async def wait_for_incident(
        self, service: str, *, opened_after: datetime, timeout_s: float = 90
    ) -> dict[str, Any]:
        return await self.poll_until(
            f"a new {service} incident",
            timeout_s,
            lambda: self.latest_incident(service, opened_after=opened_after),
        )

    async def wait_for_proposed_action(self, ref: str, *, timeout_s: float = 90) -> dict[str, Any]:
        async def check() -> dict[str, Any] | None:
            actions = await self.actions_for(ref)
            return actions[0] if actions else None  # newest first

        return await self.poll_until(f"a proposed action on {ref}", timeout_s, check)

    async def wait_for_investigation(self, ref: str, *, timeout_s: float = 90) -> dict[str, Any]:
        async def check() -> dict[str, Any] | None:
            for inv in await self.investigations_for(ref):
                if inv["status"] in ("succeeded", "failed"):
                    return inv
            return None

        return await self.poll_until(f"a completed investigation on {ref}", timeout_s, check)

    _STALLED_ACTION_STATUSES = frozenset(
        {"verification_failed", "failed", "rejected", "expired", "cancelled"}
    )

    async def wait_for_resolution(
        self,
        ref: str,
        *,
        timeout_s: float = 180,
        on_status: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Poll until the incident resolves/closes, or its newest action reaches a
        terminal non-recovering state (whichever happens first — the latter raises
        `DemoStalledError` instead of running out the clock as a bare timeout, since
        it's immediately diagnosable: most often dry-run mode, where execution is a
        deliberate no-op and verification is therefore correct to never pass)."""
        last_status: str | None = None
        deadline = time.monotonic() + timeout_s
        while True:
            detail = await self.incident_detail(ref)
            if detail["status"] != last_status:
                last_status = detail["status"]
                if on_status:
                    on_status(last_status)
            if detail["status"] in ("resolved", "closed"):
                return detail
            actions = await self.actions_for(ref)
            if actions and actions[0]["status"] in self._STALLED_ACTION_STATUSES:
                newest = actions[0]
                dry_run_note = (
                    " (it ran in DRY-RUN mode — the fleet was never actually changed, "
                    "so recovery correctly never verifies; set "
                    "SENTINEL_EXECUTION_MODE=live to see a real fix)"
                    if newest.get("dry_run")
                    else ""
                )
                raise DemoStalledError(
                    f"{ref}: action {newest['runbook_id']} reached "
                    f"'{newest['status']}' with nothing further queued{dry_run_note}"
                )
            if time.monotonic() >= deadline:
                raise DemoTimeoutError(
                    f"timed out after {timeout_s:.0f}s waiting for: {ref} to resolve"
                )
            await asyncio.sleep(self._cfg.poll_interval_s)
