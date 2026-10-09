"""Docker API guard: an admission controller between the actuator and the socket proxy.

    actuator -> docker-guard (body/target checks) -> socket-proxy-rw (path allowlist) -> docker

The socket proxy filters requests by HTTP method and path only. That leaves two gaps,
both of which were confirmed by probing the live stack:
  1. `POST /containers/create` with `Privileged: true` (or devices, host namespaces,
     capabilities...) passes a path filter.
  2. Stop/restart/delete of *any* container (e.g. unrelated workloads on the same
     daemon) passes a path filter.
The guard closes both. It validates create bodies against a strict allowlist, and it
inspects the target of every mutating per-container call, refusing anything not
labelled `sentinel.managed=true`. It runs as a separate process with no Docker
socket, so even a compromised actuator is bound by it.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, generate_latest
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from actuator.catalog import ALLOWED_CONFIG_KEYS

log = logging.getLogger("actuator.guard")

MAX_BODY_BYTES = 64 * 1024
# Env vars the fleet manager sets itself, plus catalogue-controlled config keys.
ALLOWED_ENV_KEYS = (
    frozenset({"SERVICE_NAME", "APP_VERSION", "CONFIG_REVISION", "REPLICA", "CHAOS_TOKEN"})
    | ALLOWED_CONFIG_KEYS
)

_V = r"(?:/v1\.[0-9]+)?"
CREATE_RE = re.compile(rf"^{_V}/containers/create$")
MUTATE_RE = re.compile(rf"^{_V}/containers/([a-zA-Z0-9_.-]+)(?:/(start|stop|restart|kill))?$")

# HostConfig keys the guard understands. Any other key must be absent or empty.
_HOST_KEYS = {
    "Memory",
    "MemorySwap",
    "NanoCpus",
    "PidsLimit",
    "CapDrop",
    "SecurityOpt",
    "ReadonlyRootfs",
    "Tmpfs",
    "RestartPolicy",
    "LogConfig",
    "Init",
    "NetworkMode",
}
# Top-level create keys that may carry values. Everything else (Cmd, Entrypoint,
# User, Volumes, WorkingDir...) must be empty, so the image defaults apply.
_TOP_KEYS = {
    "Image",
    "Env",
    "Labels",
    "HostConfig",
    "NetworkingConfig",
    "AttachStdout",
    "AttachStderr",  # docker-py defaults; stream-attach flags only
}


class GuardSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GUARD_", frozen=True, extra="ignore")

    upstream: str = "http://socket-proxy-rw:2375"
    image_pattern: str = r"^sentinel/shop-api:[0-9A-Za-z._-]{1,64}$"
    allowed_networks: frozenset[str] = frozenset({"sentinel-app"})
    max_memory_mb: int = Field(default=1024, ge=32)
    max_cpus: float = Field(default=2.0, gt=0)
    max_pids: int = Field(default=1024, ge=16)
    port: int = 2375
    log_level: str = "INFO"


class GuardViolationError(Exception):
    """Request refused by guard policy."""


def _empty(value: Any) -> bool:
    return value in (None, False, "", 0, [], {}, "default") or value == {"Name": ""}


def validate_create(body: dict[str, Any], s: GuardSettings, name: str | None) -> None:
    """Raise GuardViolationError unless the container spec is within policy."""
    for key, value in body.items():
        if key not in _TOP_KEYS and not _empty(value):
            raise GuardViolationError(f"field {key!r} is not permitted")

    image = body.get("Image") or ""
    if not re.fullmatch(s.image_pattern, image):
        raise GuardViolationError(f"image {image!r} is not allowlisted")

    labels = body.get("Labels") or {}
    if labels.get("sentinel.managed") != "true":
        raise GuardViolationError("container must carry sentinel.managed=true")
    if name is None or not re.fullmatch(r"[a-z0-9-]{1,40}-[0-9]{1,2}", name):
        raise GuardViolationError(
            f"container name {name!r} does not match the managed naming scheme"
        )

    env_keys = {str(e).split("=", 1)[0] for e in body.get("Env") or []}
    if bad := env_keys - ALLOWED_ENV_KEYS:
        raise GuardViolationError(f"environment keys not permitted: {sorted(bad)}")

    host = body.get("HostConfig") or {}
    for key, value in host.items():
        if key not in _HOST_KEYS and not _empty(value):
            raise GuardViolationError(f"HostConfig.{key} is not permitted")
    if host.get("CapDrop") != ["ALL"]:
        raise GuardViolationError("HostConfig.CapDrop must be ['ALL']")
    secopts = host.get("SecurityOpt") or []
    if not any(o.replace("=", ":") == "no-new-privileges:true" for o in secopts):
        raise GuardViolationError("no-new-privileges is required")
    if any(o != "no-new-privileges:true" for o in secopts):
        raise GuardViolationError(f"unexpected SecurityOpt {secopts}")
    if host.get("ReadonlyRootfs") is not True:
        raise GuardViolationError("read-only root filesystem is required")
    memory = int(host.get("Memory") or 0)
    if not 0 < memory <= s.max_memory_mb * 2**20:
        raise GuardViolationError("memory limit missing or too large")
    if int(host.get("MemorySwap") or 0) != memory:
        raise GuardViolationError("swap must be disabled (MemorySwap == Memory)")
    if not 0 < int(host.get("NanoCpus") or 0) <= s.max_cpus * 1e9:
        raise GuardViolationError("CPU limit missing or too large")
    if not 0 < int(host.get("PidsLimit") or 0) <= s.max_pids:
        raise GuardViolationError("pids limit missing or too large")
    if (mode := host.get("NetworkMode")) not in (None, "default", *s.allowed_networks):
        raise GuardViolationError(f"network mode {mode!r} is not permitted")
    for mount, opts in (host.get("Tmpfs") or {}).items():
        if mount != "/tmp" or "noexec" not in opts:  # nosec B108 # noqa: S108
            raise GuardViolationError(f"tmpfs {mount!r} not permitted")

    endpoints = ((body.get("NetworkingConfig") or {}).get("EndpointsConfig")) or {}
    if bad_nets := set(endpoints) - s.allowed_networks:
        raise GuardViolationError(f"networks not permitted: {sorted(bad_nets)}")


def create_guard_app(
    settings: GuardSettings, transport: httpx.AsyncBaseTransport | None = None
) -> FastAPI:
    registry = CollectorRegistry()
    decisions = Counter(
        "docker_guard_requests_total",
        "Guard decisions.",
        ["decision", "method"],
        registry=registry,
    )
    client = httpx.AsyncClient(base_url=settings.upstream, timeout=60.0, transport=transport)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        await client.aclose()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    def deny(method: str, path: str, reason: str) -> JSONResponse:
        decisions.labels("denied", method).inc()
        log.warning("denied", extra={"method": method, "path": path, "reason": reason})
        # Docker API error shape, so clients surface the reason.
        return JSONResponse({"message": f"sentinel docker-guard: {reason}"}, status_code=403)

    @app.get("/_guard/metrics")
    async def metrics() -> Response:
        return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)

    @app.get("/_guard/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.api_route("/{path:path}", methods=["GET", "HEAD", "POST", "DELETE"])
    async def proxy(request: Request, path: str) -> Response:
        method = request.method
        url_path = "/" + path
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            return deny(method, url_path, "request body too large")

        if method == "POST" and CREATE_RE.fullmatch(url_path):
            try:
                spec = json.loads(body or b"{}")
                if not isinstance(spec, dict):
                    raise GuardViolationError("body must be a JSON object")
                validate_create(spec, settings, request.query_params.get("name"))
            except (GuardViolationError, ValueError) as exc:
                return deny(method, url_path, str(exc))
        elif method in ("POST", "DELETE") and (m := MUTATE_RE.fullmatch(url_path)):
            target = m.group(1)
            r = await client.get(f"/containers/{target}/json")
            if r.status_code != 200:
                return deny(method, url_path, f"cannot verify target {target!r}")
            labels = (r.json().get("Config") or {}).get("Labels") or {}
            if labels.get("sentinel.managed") != "true":
                return deny(method, url_path, f"container {target!r} is not sentinel-managed")
        elif method in ("POST", "DELETE"):
            return deny(method, url_path, "operation not permitted")

        upstream = await client.request(
            method,
            url_path,
            params=request.query_params,
            content=body,
            headers={
                k: v for k, v in request.headers.items() if k.lower() in ("content-type", "accept")
            },
        )
        decisions.labels("allowed", method).inc()
        return Response(
            upstream.content,
            status_code=upstream.status_code,
            headers={
                k: v
                for k, v in upstream.headers.items()
                if k.lower() in ("content-type", "api-version", "docker-experimental", "ostype")
            },
        )

    return app


def main() -> int:
    settings = GuardSettings()
    logging.basicConfig(
        level=settings.log_level,
        stream=sys.stdout,
        format='{"level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
    )
    uvicorn.run(
        create_guard_app(settings),
        host="0.0.0.0",  # nosec B104 # noqa: S104 (internal network)
        port=settings.port,
        log_config=None,
        access_log=False,
        server_header=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
