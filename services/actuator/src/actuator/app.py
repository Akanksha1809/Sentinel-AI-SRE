"""Actuator HTTP API.

Two credentials with different scopes:
- `actuator_token`: remediation (restart / rollback / scale). Held by Sentinel.
- `fault_token`: demo fault injection (arbitrary catalogue deploys, chaos forwarding).
  Held only by the demo CLI. Sentinel never receives it.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import asdict
from typing import Annotated, Any, Literal

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Path, Query, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, generate_latest
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from actuator.catalog import NAME, REVISION, VERSION, UnknownTargetError
from actuator.fleet import (
    ActionResult,
    BoundsError,
    DeploymentEvent,
    FleetManager,
    PreconditionError,
)
from actuator.runtime import NotManagedError, RuntimeUnavailableError
from actuator.telemetry import FleetCollector, FleetObserver

log = logging.getLogger("actuator")


class _Req(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service: str = Field(pattern=NAME)
    dry_run: bool = False


class RestartRequest(_Req):
    replica: int | None = Field(default=None, ge=1, le=5)


class RollbackRequest(_Req):
    target_version: str = Field(pattern=VERSION)
    target_config_revision: str | None = Field(default=None, pattern=REVISION)


class ScaleRequest(_Req):
    replicas: int = Field(ge=1, le=5)  # tighter per-service bounds enforced by FleetManager


class DeployRequest(_Req):
    version: str = Field(pattern=VERSION)
    config_revision: str = Field(pattern=REVISION)
    change_ref: str | None = Field(default=None, max_length=120)


ChaosMode = Literal["memory", "latency", "cpu"]


def _bearer_checker(secret: SecretStr | None, scope: str) -> Callable[..., str]:
    def check(
        authorization: Annotated[str | None, Header()] = None,
        x_actor: Annotated[str | None, Header(max_length=80)] = None,
    ) -> str:
        if secret is None:
            raise HTTPException(403, f"{scope} API disabled (no token configured)")
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(
            token.encode(), secret.get_secret_value().encode()
        ):
            raise HTTPException(401, "invalid credentials", headers={"WWW-Authenticate": "Bearer"})
        return f"{scope}:{x_actor or 'anonymous'}"

    return check


def create_app(
    fleet: FleetManager,
    *,
    actuator_token: SecretStr | None,
    fault_token: SecretStr | None,
    chaos_token: SecretStr | None,
    poll_interval_s: float = 5.0,
    reconcile_on_start: bool = True,
    start_background: bool = True,
    replica_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    registry = CollectorRegistry(auto_describe=True)
    observer = FleetObserver(fleet, registry)
    registry.register(FleetCollector(observer, fleet))
    actions = Counter(
        "fleet_actions_total",
        "Actuator actions.",
        ["action", "outcome", "dry_run"],
        registry=registry,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        task: asyncio.Task[None] | None = None
        if start_background:
            if reconcile_on_start:
                for attempt in range(1, 6):
                    try:
                        await fleet.reconcile_initial()
                        break
                    except Exception:
                        log.warning(
                            "initial reconcile failed", extra={"attempt": attempt}, exc_info=True
                        )
                        await asyncio.sleep(2 * attempt)
            await observer.poll_once()
            task = asyncio.create_task(observer.run(poll_interval_s), name="fleet-poller")
        app.state.ready = True
        yield
        if task:
            task.cancel()

    app = FastAPI(title="sentinel-actuator", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.ready = False
    app.state.observer = observer

    remediation = Depends(_bearer_checker(actuator_token, "remediation"))
    faults = Depends(_bearer_checker(fault_token, "faults"))

    @app.exception_handler(UnknownTargetError)
    async def _unknown(_: Request, exc: UnknownTargetError) -> JSONResponse:
        return JSONResponse({"error": "unknown_target", "detail": str(exc)}, 404)

    @app.exception_handler(BoundsError)
    async def _bounds(_: Request, exc: BoundsError) -> JSONResponse:
        return JSONResponse({"error": "out_of_bounds", "detail": str(exc)}, 422)

    @app.exception_handler(PreconditionError)
    async def _precondition(_: Request, exc: PreconditionError) -> JSONResponse:
        return JSONResponse({"error": "precondition_failed", "detail": str(exc)}, 409)

    @app.exception_handler(NotManagedError)
    async def _unmanaged(_: Request, exc: NotManagedError) -> JSONResponse:
        return JSONResponse({"error": "not_managed", "detail": str(exc)}, 403)

    @app.exception_handler(RuntimeUnavailableError)
    async def _unavailable(_: Request, exc: RuntimeUnavailableError) -> JSONResponse:
        return JSONResponse({"error": "runtime_unavailable", "detail": str(exc)}, 503)

    async def _record(kind: str, dry_run: bool, coro: Any) -> dict[str, Any]:
        try:
            result: ActionResult = await coro
        except Exception:
            actions.labels(kind, "error", str(dry_run).lower()).inc()
            raise
        outcome = "changed" if result.changed else ("planned" if dry_run else "noop")
        actions.labels(kind, outcome, str(dry_run).lower()).inc()
        await observer.poll_once()
        log.info(
            "action",
            extra={
                "action": kind,
                "service": result.service,
                "outcome": outcome,
                "plan": result.plan,
            },
        )
        return result.to_dict()

    # ---- read-only ----------------------------------------------------------
    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        ok = bool(app.state.ready) and bool(observer.cache)
        return JSONResponse({"status": "ready" if ok else "starting"}, 200 if ok else 503)

    @app.get("/metrics")
    async def metrics() -> Response:
        return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)

    @app.get("/v1/sd/targets")
    async def sd_targets() -> list[dict[str, object]]:
        return observer.sd_targets({n: s.port for n, s in fleet.catalog.services.items()})

    @app.get("/v1/fleet")
    async def fleet_state() -> list[dict[str, Any]]:
        return [(await fleet.snapshot(n)).to_dict() for n in fleet.catalog.services]

    @app.get("/v1/releases/{service}")
    async def releases(service: str) -> dict[str, Any]:
        svc = fleet.catalog.service(service)
        return {
            "service": service,
            "versions": sorted(svc.releases),
            "config_revisions": sorted(svc.config_revisions),
            "replicas": {"min": svc.min_replicas, "max": svc.max_replicas},
        }

    @app.get("/v1/deployments")
    async def deployments(
        service: str | None = None, limit: Annotated[int, Query(ge=1, le=200)] = 50
    ) -> list[dict[str, Any]]:
        events = [asdict(e) for e in fleet.history if service is None or e.service == service]
        return list(reversed(events))[:limit]

    # ---- remediation (Sentinel) --------------------------------------------
    @app.post("/v1/actions/restart")
    async def restart(req: RestartRequest, actor: str = remediation) -> dict[str, Any]:
        return await _record(
            "restart",
            req.dry_run,
            fleet.restart(req.service, req.replica, actor=actor, dry_run=req.dry_run),
        )

    @app.post("/v1/actions/rollback")
    async def rollback(req: RollbackRequest, actor: str = remediation) -> dict[str, Any]:
        return await _record(
            "rollback",
            req.dry_run,
            fleet.rollback(
                req.service,
                req.target_version,
                req.target_config_revision,
                actor=actor,
                dry_run=req.dry_run,
            ),
        )

    @app.post("/v1/actions/scale")
    async def scale(req: ScaleRequest, actor: str = remediation) -> dict[str, Any]:
        return await _record(
            "scale",
            req.dry_run,
            fleet.scale(req.service, req.replicas, actor=actor, dry_run=req.dry_run),
        )

    # ---- fault injection (demo CLI only) -----------------------------------
    @app.post("/v1/deploy")
    async def deploy(req: DeployRequest, actor: str = faults) -> dict[str, Any]:
        return await _record(
            "deploy",
            req.dry_run,
            fleet.deploy(
                req.service,
                req.version,
                req.config_revision,
                actor=actor,
                dry_run=req.dry_run,
                change_ref=req.change_ref,
            ),
        )

    async def _forward_chaos(
        service: str, method: str, path: str, replica: int | None, body: dict[str, Any] | None
    ) -> list[dict[str, Any]]:
        if chaos_token is None:
            raise HTTPException(403, "chaos token not configured")
        svc = fleet.catalog.service(service)
        snap = await fleet.snapshot(service)
        targets = [
            c
            for c in snap.containers
            if c.status == "running" and (replica is None or c.replica == replica)
        ]
        if not targets:
            raise HTTPException(409, "no running replicas match")
        results = []
        async with httpx.AsyncClient(timeout=5.0, transport=replica_transport) as client:
            for c in targets:
                # A replica reported "running" can still be unreachable for a moment
                # (e.g. right after a deploy replaced it and its HTTP server hasn't
                # bound yet); that's one replica's bad luck, not a reason to fail the
                # whole fan-out or crash the connection the caller is waiting on.
                try:
                    r = await client.request(
                        method,
                        f"http://{c.name}:{svc.port}{path}",
                        json=body,
                        headers={"X-Chaos-Token": chaos_token.get_secret_value()},
                    )
                except httpx.TransportError as exc:
                    results.append({"replica": c.replica, "status": None, "error": str(exc)})
                    continue
                results.append(
                    {
                        "replica": c.replica,
                        "status": r.status_code,
                        "response": r.json() if r.content else None,
                    }
                )
        return results

    @app.post("/v1/faults/{service}/chaos/{mode}")
    async def inject_chaos(
        service: Annotated[str, Path(pattern=NAME)],
        mode: ChaosMode,
        request: Request,
        _actor: str = faults,
        replica: Annotated[int | None, Query(ge=1, le=5)] = None,
    ) -> list[dict[str, Any]]:
        raw = await request.body()
        if len(raw) > 4096:
            raise HTTPException(413, "payload too large")
        body = await request.json() if raw else {}
        if not isinstance(body, dict):
            raise HTTPException(422, "body must be a JSON object")
        return await _forward_chaos(service, "POST", f"/chaos/{mode}", replica, body)

    @app.delete("/v1/faults/{service}/chaos")
    async def clear_chaos(
        service: str,
        _actor: str = faults,
        replica: Annotated[int | None, Query(ge=1, le=5)] = None,
    ) -> list[dict[str, Any]]:
        return await _forward_chaos(service, "DELETE", "/chaos", replica, None)

    return app


def make_event_sink(url: str, token: SecretStr | None) -> Callable[[DeploymentEvent], Any]:
    """Best-effort delivery of deployment events to Sentinel, with bounded retries."""

    async def sink(event: DeploymentEvent) -> None:
        headers = {"Authorization": f"Bearer {token.get_secret_value()}"} if token else {}
        async with httpx.AsyncClient(timeout=5.0) as client:
            for attempt in range(3):
                try:
                    r = await client.post(url, json=asdict(event), headers=headers)
                    if r.status_code < 500:
                        r.raise_for_status()
                        return
                except httpx.HTTPStatusError:
                    raise
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.5 * 2**attempt)
            raise RuntimeError(f"deployment event delivery to {url} failed after 3 attempts")

    return sink
