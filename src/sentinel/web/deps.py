"""Web UI auth dependencies: session cookie -> WebIdentity, plus CSRF enforcement.

Deliberately separate from `sentinel.api.deps` (Bearer tokens): a stolen session
cookie should never work against `/api/v1/*`, and a leaked API token should never
let someone drive the browser UI session-less.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Cookie, Depends, HTTPException, Request

from sentinel.api.deps import ContainerDep
from sentinel.container import Container
from sentinel.domain.enums import Role
from sentinel.web.session import COOKIE_NAME, CSRF_FIELD, WebIdentity, csrf_token_for, verify_csrf
from sentinel.web.session import verify_session_cookie as _verify


class LoginRequiredError(Exception):
    """No valid session; an exception handler redirects to /login?next=..."""


def _secret(container: Container) -> str:
    if container.settings.ui_secret is None:
        raise HTTPException(503, "web UI is not configured (no ui_secret)")
    return container.settings.ui_secret.get_secret_value()


def require_web_role(role: Role) -> Callable[..., Awaitable[WebIdentity]]:
    async def dependency(
        container: ContainerDep,
        session_cookie: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None,
    ) -> WebIdentity:
        if session_cookie is None:
            raise LoginRequiredError
        identity = _verify(
            _secret(container), session_cookie, max_age=container.settings.ui_session_max_age_s
        )
        if identity is None:
            raise LoginRequiredError
        if not identity.role.satisfies(role):
            raise HTTPException(403, f"requires role {role.value} or higher")
        return identity

    return dependency


WebViewer = Annotated[WebIdentity, Depends(require_web_role(Role.VIEWER))]
WebResponder = Annotated[WebIdentity, Depends(require_web_role(Role.RESPONDER))]
WebApprover = Annotated[WebIdentity, Depends(require_web_role(Role.APPROVER))]
WebAdmin = Annotated[WebIdentity, Depends(require_web_role(Role.ADMIN))]


async def get_csrf_token(
    container: ContainerDep,
    session_cookie: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None,
) -> str:
    """Embedded as a hidden field in every form; empty (and so always rejected) when
    there's no session to bind it to."""
    if session_cookie is None or container.settings.ui_secret is None:
        return ""
    return csrf_token_for(container.settings.ui_secret.get_secret_value(), session_cookie)


CsrfToken = Annotated[str, Depends(get_csrf_token)]


async def require_csrf(
    request: Request,
    container: ContainerDep,
    session_cookie: Annotated[str | None, Cookie(alias=COOKIE_NAME)] = None,
) -> None:
    """Every state-changing route depends on this. Reads the already-parsed form
    body (FastAPI/Starlette cache it, so this doesn't consume the stream twice)."""
    form = await request.form()
    provided = form.get(CSRF_FIELD)
    if (
        session_cookie is None
        or not isinstance(provided, str)
        or not verify_csrf(_secret(container), session_cookie, provided)
    ):
        raise HTTPException(403, "missing or invalid CSRF token; reload the page and try again")
