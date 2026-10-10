"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from sentinel import __version__
from sentinel.api import errors
from sentinel.api.routes import actions, admin, incidents, investigations, webhooks
from sentinel.container import Container
from sentinel.domain.enums import Role
from sentinel.observability.middleware import ObservabilityMiddleware
from sentinel.security import BOOTSTRAP_ADMIN, upsert_principal

log = structlog.get_logger("sentinel.api")


async def bootstrap_admin(container: Container) -> None:
    token = container.settings.bootstrap_admin_token
    if token is None:
        log.warning("no bootstrap admin token configured; create principals with the CLI")
        return
    async with container.sessions.begin() as session:
        await upsert_principal(
            session, container.clock, BOOTSTRAP_ADMIN, Role.ADMIN, token.get_secret_value()
        )
        await container.audit.append(
            session,
            actor="system",
            action="principal.bootstrapped",
            subject_type="principal",
            subject_id=BOOTSTRAP_ADMIN,
        )


def create_app(container: Container, *, run_bootstrap: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if run_bootstrap:
            await bootstrap_admin(container)
        log.info(
            "sentinel api started",
            version=__version__,
            environment=container.settings.environment,
            webhook_auth=container.settings.webhook_token is not None,
        )
        yield
        await container.engine.dispose()

    app = FastAPI(
        title="Sentinel",
        version=__version__,
        description="AI-assisted SRE incident response platform",
        lifespan=lifespan,
        openapi_url="/api/v1/openapi.json",
        docs_url="/api/docs",
        redoc_url=None,
    )
    app.state.container = container
    container.metrics.build.labels(__version__).set(1)
    errors.install(app)
    app.add_middleware(ObservabilityMiddleware, metrics=container.metrics)
    for router in (
        admin.health,
        webhooks.router,
        incidents.router,
        admin.deployments,
        admin.audit,
        investigations.router,
        actions.router,
    ):
        app.include_router(router)
    return app
