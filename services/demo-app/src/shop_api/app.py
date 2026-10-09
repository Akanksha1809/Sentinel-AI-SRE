"""shop-api FastAPI application factory."""

from __future__ import annotations

import asyncio
import hmac
import logging
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field

from shop_api.catalog import Catalog
from shop_api.chaos import ChaosEngine, ChaosLimitError, CpuFault, LatencyFault, MemoryFault
from shop_api.config import Settings
from shop_api.logs import request_id_var
from shop_api.metrics import Metrics

log = logging.getLogger("shop_api")

_REQUEST_ID_MAX = 64


class CheckoutRequest(BaseModel):
    product_id: int = Field(ge=1, le=1000)
    quantity: int = Field(default=1, ge=1, le=10)


def create_app(settings: Settings, chaos: ChaosEngine | None = None) -> FastAPI:
    metrics = Metrics()
    catalog = Catalog(settings.release_defect)
    engine = chaos or ChaosEngine(settings.chaos_max_memory_mb, settings.chaos_max_duration_s)
    metrics.app_info.labels(
        settings.app_version, settings.config_revision, settings.release_defect
    ).set(1)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        log.info(
            "service started",
            extra={"pool_size": settings.pool_size, "release_defect": settings.release_defect},
        )
        app.state.ready = True
        yield
        app.state.ready = False
        engine.clear()
        log.info("service stopping")

    app = FastAPI(
        title="shop-api",
        version=settings.app_version,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
    )
    app.state.ready = False
    app.state.chaos = engine

    # ---- middleware: request id, RED metrics, access/error logs ------------
    @app.middleware("http")
    async def observe(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        incoming = request.headers.get("x-request-id", "")
        rid = (
            incoming
            if 0 < len(incoming) <= _REQUEST_ID_MAX and incoming.isprintable()
            else uuid.uuid4().hex
        )
        token = request_id_var.set(rid)
        start = time.perf_counter()
        metrics.in_progress.inc()
        try:
            try:
                response = await call_next(request)
            except Exception:
                log.exception("unhandled error", extra={"path": request.url.path})
                response = JSONResponse({"error": "internal_error", "request_id": rid}, 500)
            route = request.scope.get("route")
            route_path = getattr(route, "path", "unmatched")
            if route_path not in ("/metrics", "/healthz", "/readyz"):
                elapsed = time.perf_counter() - start
                metrics.requests.labels(request.method, route_path, str(response.status_code)).inc()
                metrics.latency.labels(request.method, route_path).observe(elapsed)
                level = logging.WARNING if response.status_code >= 500 else logging.INFO
                log.log(
                    level,
                    "request",
                    extra={
                        "method": request.method,
                        "route": route_path,
                        "status": response.status_code,
                        "duration_ms": round(elapsed * 1000, 2),
                    },
                )
            response.headers["X-Request-ID"] = rid
            return response
        finally:
            metrics.in_progress.dec()
            request_id_var.reset(token)

    async def simulated_work(base_s: float) -> None:
        await asyncio.sleep(base_s + engine.injected_latency_s())

    # ---- business endpoints ------------------------------------------------
    @app.get("/products")
    async def list_products() -> list[dict[str, Any]]:
        await simulated_work(0.005)
        return [{"id": p.id, "name": p.name, "price_cents": p.price_cents} for p in catalog.list()]

    @app.get("/products/{product_id}")
    async def get_product(product_id: int) -> dict[str, Any]:
        await simulated_work(0.004)
        product = catalog.get(product_id)
        if product is None:
            raise HTTPException(404, "product not found")
        return {"id": product.id, "name": product.name, "price_cents": product.price_cents}

    @app.post("/checkout")
    async def checkout(body: CheckoutRequest) -> dict[str, Any]:
        await simulated_work(0.012)
        product = catalog.get(body.product_id)
        if product is None:
            metrics.checkouts.labels("not_found").inc()
            raise HTTPException(404, "product not found")
        try:
            total = catalog.checkout_total(product, body.quantity)
        except Exception:
            metrics.checkouts.labels("error").inc()
            raise
        metrics.checkouts.labels("success").inc()
        return {"order_id": uuid.uuid4().hex, "product_id": product.id, "total_cents": total}

    # ---- ops endpoints -----------------------------------------------------
    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        ready = bool(app.state.ready)
        return JSONResponse({"status": "ready" if ready else "starting"}, 200 if ready else 503)

    @app.get("/metrics")
    async def prom_metrics() -> Response:
        state = engine.state()
        metrics.chaos_memory.set(state["memory"]["allocated_bytes"])
        for mode in ("memory", "latency", "cpu"):
            metrics.chaos_active.labels(mode).set(1 if state[mode]["active"] else 0)
        return Response(generate_latest(metrics.registry), media_type=CONTENT_TYPE_LATEST)

    # ---- chaos (token-protected, bounded) ----------------------------------
    def require_chaos_token(
        x_chaos_token: Annotated[str | None, Header()] = None,
    ) -> None:
        expected = settings.chaos_token
        if expected is None:
            raise HTTPException(403, "chaos endpoints are disabled")
        if x_chaos_token is None or not hmac.compare_digest(
            x_chaos_token.encode(), expected.get_secret_value().encode()
        ):
            raise HTTPException(401, "invalid chaos token")

    chaos_auth = [Depends(require_chaos_token)]

    def limited(exc: ChaosLimitError) -> HTTPException:
        return HTTPException(422, str(exc))

    @app.get("/chaos", dependencies=chaos_auth)
    async def chaos_state() -> dict[str, Any]:
        return engine.state()

    @app.post("/chaos/memory", dependencies=chaos_auth, status_code=202)
    async def chaos_memory(fault: MemoryFault) -> dict[str, Any]:
        try:
            await engine.start_memory(fault)
        except ChaosLimitError as exc:
            raise limited(exc) from exc
        log.warning("chaos.memory started", extra=fault.model_dump())
        return engine.state()

    @app.post("/chaos/latency", dependencies=chaos_auth, status_code=202)
    async def chaos_latency(fault: LatencyFault) -> dict[str, Any]:
        try:
            engine.start_latency(fault)
        except ChaosLimitError as exc:
            raise limited(exc) from exc
        log.warning("chaos.latency started", extra=fault.model_dump())
        return engine.state()

    @app.post("/chaos/cpu", dependencies=chaos_auth, status_code=202)
    async def chaos_cpu(fault: CpuFault) -> dict[str, Any]:
        try:
            engine.start_cpu(fault)
        except ChaosLimitError as exc:
            raise limited(exc) from exc
        log.warning("chaos.cpu started", extra=fault.model_dump())
        return engine.state()

    @app.delete("/chaos", dependencies=chaos_auth)
    async def chaos_clear() -> dict[str, Any]:
        engine.clear()
        log.warning("chaos cleared")
        return engine.state()

    return app
