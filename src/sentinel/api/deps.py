"""FastAPI dependencies: container access and authentication."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request

from sentinel.container import Container
from sentinel.domain.enums import Role
from sentinel.security import Identity, authenticate, constant_time_equals


def get_container(request: Request) -> Container:
    container: Container = request.app.state.container
    return container


ContainerDep = Annotated[Container, Depends(get_container)]


def _bearer(authorization: str | None) -> str | None:
    scheme, _, token = (authorization or "").partition(" ")
    return token.strip() or None if scheme.lower() == "bearer" else None


def _unauthorized(detail: str = "missing or invalid credentials") -> HTTPException:
    return HTTPException(401, detail, headers={"WWW-Authenticate": "Bearer"})


def require_role(role: Role) -> Callable[..., Awaitable[Identity]]:
    async def dependency(
        container: ContainerDep,
        authorization: Annotated[str | None, Header()] = None,
    ) -> Identity:
        token = _bearer(authorization)
        if token is None:
            raise _unauthorized()
        async with container.sessions() as session:
            identity = await authenticate(session, token)
        if identity is None:
            raise _unauthorized()
        if not identity.role.satisfies(role):
            raise HTTPException(403, f"requires role {role.value} or higher")
        return identity

    return dependency


Viewer = Annotated[Identity, Depends(require_role(Role.VIEWER))]
Responder = Annotated[Identity, Depends(require_role(Role.RESPONDER))]
Approver = Annotated[Identity, Depends(require_role(Role.APPROVER))]
Admin = Annotated[Identity, Depends(require_role(Role.ADMIN))]


async def require_webhook_token(
    container: ContainerDep,
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    """Alertmanager credential: a dedicated static token. Fails closed if unconfigured."""
    if not constant_time_equals(_bearer(authorization), container.settings.webhook_token):
        container.metrics.webhook_rejected.labels("unauthorized").inc()
        raise _unauthorized()
    return "alertmanager"


async def require_deployer(
    container: ContainerDep,
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    """Deployment events: the actuator's deployer token, or any admin principal."""
    token = _bearer(authorization)
    if constant_time_equals(token, container.settings.deployer_token):
        return "deployer:actuator"
    if token:
        async with container.sessions() as session:
            identity = await authenticate(session, token)
        if identity and identity.role.satisfies(Role.ADMIN):
            return identity.actor
    raise _unauthorized()
