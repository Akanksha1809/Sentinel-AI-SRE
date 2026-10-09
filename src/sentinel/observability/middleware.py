"""ASGI middleware: correlation IDs, RED metrics, access logs."""

from __future__ import annotations

import re
import time
import uuid

import structlog
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sentinel.observability.context import correlation_id_var
from sentinel.observability.metrics import Metrics

_CID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_QUIET = {"/healthz", "/readyz", "/metrics"}
log = structlog.get_logger("sentinel.access")


class ObservabilityMiddleware:
    def __init__(self, app: ASGIApp, metrics: Metrics) -> None:
        self.app = app
        self.metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        incoming = headers.get(b"x-correlation-id", b"").decode("latin-1")
        cid = incoming if _CID.match(incoming) else uuid.uuid4().hex
        token = correlation_id_var.set(cid)
        status = 500
        start = time.perf_counter()

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                message.setdefault("headers", []).append((b"x-correlation-id", cid.encode()))
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            route = scope.get("route")
            path = getattr(route, "path", "unmatched")
            elapsed = time.perf_counter() - start
            self.metrics.http_requests.labels(scope["method"], path, str(status)).inc()
            self.metrics.http_latency.labels(scope["method"], path).observe(elapsed)
            if path not in _QUIET:
                log.info(
                    "request",
                    method=scope["method"],
                    route=path,
                    status=status,
                    duration_ms=round(elapsed * 1000, 2),
                )
            correlation_id_var.reset(token)
