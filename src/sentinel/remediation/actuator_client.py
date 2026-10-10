"""HTTP client for the actuator's remediation API (threat model T5, T8).

Sentinel never touches Docker. It calls exactly the three restricted endpoints the
actuator exposes, each bounded to the catalogue/parameters already validated by
`investigation.validate` / `ActionService.propose`. Errors are classified so the
executor retries only what might be transient (timeouts, connection failures, 503)
and fails fast on everything else (bad target, out of bounds, not managed).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import httpx


class ActuatorError(RuntimeError):
    """Terminal: retrying will not help (bad request, unknown target, bounds, not managed)."""


class ActuatorUnavailableError(RuntimeError):
    """Transient: timeout, connection failure, or a 503 from the actuator itself."""


@dataclass(frozen=True)
class ActuatorResult:
    action: str
    service: str
    dry_run: bool
    changed: bool
    plan: list[str]
    raw: dict[str, Any]


class ActuatorClient(Protocol):
    async def restart(
        self, service: str, replica: int | None, *, actor: str, dry_run: bool
    ) -> ActuatorResult: ...

    async def rollback(
        self,
        service: str,
        target_version: str,
        target_config_revision: str | None,
        *,
        actor: str,
        dry_run: bool,
    ) -> ActuatorResult: ...

    async def scale(
        self, service: str, replicas: int, *, actor: str, dry_run: bool
    ) -> ActuatorResult: ...

    async def aclose(self) -> None: ...


_ERROR_STATUS = {
    404: "unknown target",
    422: "out of bounds",
    403: "not managed",
    409: "precondition failed (e.g. image not available)",
}


class HttpActuatorClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout_s: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url,
            timeout=timeout_s,
            transport=transport,
            headers={"Authorization": f"Bearer {token}"},
        )

    async def _post(self, path: str, body: dict[str, Any], actor: str) -> ActuatorResult:
        try:
            resp = await self._client.post(path, json=body, headers={"X-Actor": actor[:80]})
        except httpx.TimeoutException as exc:
            raise ActuatorUnavailableError(f"actuator timed out calling {path}") from exc
        except httpx.TransportError as exc:
            raise ActuatorUnavailableError(f"actuator unreachable: {type(exc).__name__}") from exc
        if resp.status_code == 503:
            raise ActuatorUnavailableError(f"actuator unavailable: {resp.text[:200]}")
        if resp.status_code >= 500:
            raise ActuatorUnavailableError(f"actuator HTTP {resp.status_code}: {resp.text[:200]}")
        if resp.status_code in _ERROR_STATUS:
            raise ActuatorError(f"{_ERROR_STATUS[resp.status_code]}: {resp.text[:300]}")
        if resp.status_code == 401:
            raise ActuatorError("actuator rejected Sentinel's remediation token")
        if resp.status_code >= 400:
            raise ActuatorError(f"actuator HTTP {resp.status_code}: {resp.text[:300]}")
        raw = resp.json()
        return ActuatorResult(
            raw["action"], raw["service"], raw["dry_run"], raw["changed"], raw.get("plan", []), raw
        )

    async def restart(
        self, service: str, replica: int | None, *, actor: str, dry_run: bool
    ) -> ActuatorResult:
        body: dict[str, Any] = {"service": service, "dry_run": dry_run}
        if replica is not None:
            body["replica"] = replica
        return await self._post("/v1/actions/restart", body, actor)

    async def rollback(
        self,
        service: str,
        target_version: str,
        target_config_revision: str | None,
        *,
        actor: str,
        dry_run: bool,
    ) -> ActuatorResult:
        body: dict[str, Any] = {
            "service": service,
            "target_version": target_version,
            "dry_run": dry_run,
        }
        if target_config_revision is not None:
            body["target_config_revision"] = target_config_revision
        return await self._post("/v1/actions/rollback", body, actor)

    async def scale(
        self, service: str, replicas: int, *, actor: str, dry_run: bool
    ) -> ActuatorResult:
        return await self._post(
            "/v1/actions/scale",
            {"service": service, "replicas": replicas, "dry_run": dry_run},
            actor,
        )

    async def aclose(self) -> None:
        await self._client.aclose()


class DryRunActuatorClient:
    """Wraps a real client but forces every call to `dry_run=True`.

    Used when the global execution mode is `dry_run`: Sentinel still calls the real
    actuator (so the plan reflects real fleet state) but nothing is ever changed.
    """

    def __init__(self, inner: ActuatorClient) -> None:
        self._inner = inner

    async def restart(
        self, service: str, replica: int | None, *, actor: str, dry_run: bool
    ) -> ActuatorResult:
        return await self._inner.restart(service, replica, actor=actor, dry_run=True)

    async def rollback(
        self,
        service: str,
        target_version: str,
        target_config_revision: str | None,
        *,
        actor: str,
        dry_run: bool,
    ) -> ActuatorResult:
        return await self._inner.rollback(
            service, target_version, target_config_revision, actor=actor, dry_run=True
        )

    async def scale(
        self, service: str, replicas: int, *, actor: str, dry_run: bool
    ) -> ActuatorResult:
        return await self._inner.scale(service, replicas, actor=actor, dry_run=True)

    async def aclose(self) -> None:
        await self._inner.aclose()
