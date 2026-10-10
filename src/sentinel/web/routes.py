"""Server-rendered pages. Business logic is never reimplemented here — every page
calls straight into the same service layer (and, for reads, the same route
functions) the JSON API uses; this module only does auth, forms, and templates.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm.exc import StaleDataError

from sentinel.api.deps import ContainerDep
from sentinel.api.routes import actions as actions_routes
from sentinel.api.routes import incidents as incidents_routes
from sentinel.api.routes import investigations as investigations_routes
from sentinel.api.schemas import AckIn, NoteIn, ResolveIn
from sentinel.container import Container
from sentinel.domain.actions import InvalidActionTransitionError
from sentinel.domain.enums import Role
from sentinel.domain.incidents import InvalidTransitionError
from sentinel.incidents.service import IncidentNotFoundError
from sentinel.remediation.runbooks import ParameterError
from sentinel.remediation.service import (
    ActionExpiredError,
    ActionLimitExceededError,
    ActionNotFoundError,
    RunbookChangedError,
)
from sentinel.reports.service import PostmortemFinalizedError, PostmortemNotFoundError
from sentinel.security import Identity, authenticate
from sentinel.web.deps import CsrfToken, WebApprover, WebResponder, WebViewer, require_csrf
from sentinel.web.session import COOKIE_NAME, WebIdentity, create_session_cookie

router = APIRouter(tags=["web"])
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
templates.env.globals["Role"] = Role

# Ordered (type, status) pairs, checked with isinstance — not a dict keyed by type,
# so this stays a plain static tuple for mypy rather than a dynamically built except.
_STATUS: tuple[tuple[type[Exception], int], ...] = (
    (IncidentNotFoundError, 404),
    (ActionNotFoundError, 404),
    (PostmortemNotFoundError, 404),
    (InvalidTransitionError, 409),
    (InvalidActionTransitionError, 409),
    (RunbookChangedError, 409),
    (ActionExpiredError, 409),
    (PostmortemFinalizedError, 409),
    (StaleDataError, 409),
    (ActionLimitExceededError, 429),
    (ParameterError, 422),
)


@contextmanager
def web_errors() -> Any:
    """Translate the same domain errors the JSON API maps to status codes into an
    `HTTPException`, so the browser gets an HTML error page (see api/errors.py)
    instead of application/problem+json."""
    try:
        yield
    except Exception as exc:
        for exc_type, status in _STATUS:
            if isinstance(exc, exc_type):
                detail = (
                    "incident was modified concurrently; retry"
                    if exc_type is StaleDataError
                    else str(exc)
                )
                raise HTTPException(status, detail) from exc
        raise


def _identity(who: WebIdentity) -> Identity:
    return Identity(who.name, who.role)


def render(
    request: Request, name: str, *, identity: WebIdentity | None, csrf_token: str = "", **ctx: Any
) -> HTMLResponse:
    container: Container = request.app.state.container
    return templates.TemplateResponse(
        request,
        name,
        {
            "identity": identity,
            "csrf_token": csrf_token,
            "execution_mode": container.settings.execution_mode,
            **ctx,
        },
    )


# ---------------------------------------------------------------------- auth


@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, next: str = "/") -> HTMLResponse:
    return render(request, "login.html", identity=None, next_path=next)


@router.post("/login", response_model=None)
async def login_submit(
    request: Request,
    container: ContainerDep,
    token: str = Form(...),
    next: str = Form(default="/"),
) -> HTMLResponse | RedirectResponse:
    if container.settings.ui_secret is None:
        return render(
            request,
            "login.html",
            identity=None,
            next_path=next,
            error="web UI is not configured on this server",
        )
    async with container.sessions() as session:
        api_identity = await authenticate(session, token)
    if api_identity is None:
        return render(
            request,
            "login.html",
            identity=None,
            next_path=next,
            error="invalid or inactive token",
        )
    cookie = create_session_cookie(
        container.settings.ui_secret.get_secret_value(), api_identity.name, api_identity.role
    )
    safe_next = next if next.startswith("/") and not next.startswith("//") else "/"
    resp = RedirectResponse(safe_next, status_code=303)
    resp.set_cookie(
        COOKIE_NAME,
        cookie,
        httponly=True,
        samesite="strict",
        secure=container.settings.cookie_secure,
        max_age=container.settings.ui_session_max_age_s,
    )
    return resp


@router.post("/logout", dependencies=[Depends(require_csrf)])
async def logout() -> RedirectResponse:
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(COOKIE_NAME)
    return resp


# ------------------------------------------------------------------ incidents


@router.get("/", response_class=HTMLResponse)
async def incidents_list(
    request: Request, container: ContainerDep, who: WebViewer, csrf_token: CsrfToken
) -> HTMLResponse:
    page = await incidents_routes.list_incidents(container, _identity(who))
    return render(
        request, "incidents_list.html", identity=who, csrf_token=csrf_token, incidents=page.items
    )


async def _detail_context(container: Container, ref: str, who: WebIdentity) -> dict[str, Any]:
    identity = _identity(who)
    incident = await incidents_routes.get_incident(ref, container, identity)
    investigations = await investigations_routes.list_investigations(ref, container, identity)
    actions = await actions_routes.list_actions(ref, container, identity)
    try:
        evidence = await incidents_routes.get_evidence(ref, container, identity, None)
    except HTTPException:
        evidence = None  # no collection yet for this incident
    return {
        "incident": incident,
        "investigations": investigations,
        "actions": actions,
        "evidence": evidence,
    }


@router.get("/incidents/{ref}", response_class=HTMLResponse)
async def incident_detail(
    ref: str, request: Request, container: ContainerDep, who: WebViewer, csrf_token: CsrfToken
) -> HTMLResponse:
    with web_errors():
        ctx = await _detail_context(container, ref, who)
    return render(request, "incident_detail.html", identity=who, csrf_token=csrf_token, **ctx)


def _redirect_to_incident(ref: str) -> RedirectResponse:
    return RedirectResponse(f"/incidents/{ref}", status_code=303)


@router.post("/incidents/{ref}/acknowledge", dependencies=[Depends(require_csrf)])
async def acknowledge(ref: str, container: ContainerDep, who: WebResponder) -> RedirectResponse:
    with web_errors():
        await incidents_routes.acknowledge(ref, AckIn(note=None), container, _identity(who))
    return _redirect_to_incident(ref)


@router.post("/incidents/{ref}/resolve", dependencies=[Depends(require_csrf)])
async def resolve(
    ref: str, container: ContainerDep, who: WebResponder, reason: str = Form(...)
) -> RedirectResponse:
    with web_errors():
        await incidents_routes.resolve(ref, ResolveIn(reason=reason), container, _identity(who))
    return _redirect_to_incident(ref)


@router.post("/incidents/{ref}/notes", dependencies=[Depends(require_csrf)])
async def add_note(
    ref: str, container: ContainerDep, who: WebResponder, text: str = Form(...)
) -> RedirectResponse:
    with web_errors():
        await incidents_routes.add_note(ref, NoteIn(text=text), container, _identity(who))
    return _redirect_to_incident(ref)


@router.post("/incidents/{ref}/evidence/refresh", dependencies=[Depends(require_csrf)])
async def refresh_evidence(
    ref: str, container: ContainerDep, who: WebResponder
) -> RedirectResponse:
    with web_errors():
        await incidents_routes.refresh_evidence(ref, container, _identity(who))
    return _redirect_to_incident(ref)


@router.post("/incidents/{ref}/investigations", dependencies=[Depends(require_csrf)])
async def request_investigation(
    ref: str, container: ContainerDep, who: WebResponder
) -> RedirectResponse:
    with web_errors():
        await investigations_routes.request_investigation(
            ref, investigations_routes.InvestigateIn(provider=None), container, _identity(who)
        )
    return _redirect_to_incident(ref)


# --------------------------------------------------------------------- actions


@router.get("/actions/{action_id}", response_class=HTMLResponse)
async def action_detail(
    action_id: uuid.UUID,
    request: Request,
    container: ContainerDep,
    who: WebViewer,
    csrf_token: CsrfToken,
) -> HTMLResponse:
    with web_errors():
        action = await actions_routes.get_action(action_id, container, _identity(who))
    current = container.catalog.get(action.runbook_id)
    return render(
        request,
        "action_detail.html",
        identity=who,
        csrf_token=csrf_token,
        action=action,
        catalog_sha256=current.sha256 if current else None,
    )


@router.post("/actions/{action_id}/approve", dependencies=[Depends(require_csrf)])
async def approve_action(
    action_id: uuid.UUID, container: ContainerDep, who: WebApprover, reason: str = Form(default="")
) -> RedirectResponse:
    with web_errors():
        await actions_routes.approve_action(
            action_id, actions_routes.ApproveIn(reason=reason or None), container, _identity(who)
        )
    return RedirectResponse(f"/actions/{action_id}", status_code=303)


@router.post("/actions/{action_id}/reject", dependencies=[Depends(require_csrf)])
async def reject_action(
    action_id: uuid.UUID, container: ContainerDep, who: WebApprover, reason: str = Form(...)
) -> RedirectResponse:
    with web_errors():
        await actions_routes.reject_action(
            action_id, actions_routes.RejectIn(reason=reason), container, _identity(who)
        )
    return RedirectResponse(f"/actions/{action_id}", status_code=303)


# ------------------------------------------------------------------ postmortem


@router.get("/incidents/{ref}/postmortem", response_class=HTMLResponse)
async def postmortem_view(
    ref: str, request: Request, container: ContainerDep, who: WebViewer, csrf_token: CsrfToken
) -> HTMLResponse:
    with web_errors():
        async with container.sessions() as session:
            iid = await incidents_routes.resolve_id(session, ref)
            postmortem = await container.postmortems.get(session, iid)
    return render(
        request,
        "postmortem.html",
        identity=who,
        csrf_token=csrf_token,
        incident_ref=ref,
        postmortem=postmortem,
    )


@router.post("/incidents/{ref}/postmortem/generate", dependencies=[Depends(require_csrf)])
async def postmortem_generate(
    ref: str, container: ContainerDep, who: WebResponder
) -> RedirectResponse:
    with web_errors():
        async with container.sessions.begin() as session:
            iid = await incidents_routes.resolve_id(session, ref)
            await container.postmortems.generate(session, iid, who.actor)
    return RedirectResponse(f"/incidents/{ref}/postmortem", status_code=303)


@router.post("/incidents/{ref}/postmortem/edit", dependencies=[Depends(require_csrf)])
async def postmortem_edit(
    ref: str, container: ContainerDep, who: WebResponder, markdown: str = Form(...)
) -> RedirectResponse:
    with web_errors():
        async with container.sessions.begin() as session:
            iid = await incidents_routes.resolve_id(session, ref)
            await container.postmortems.edit(session, iid, markdown, who.actor, finalize=False)
    return RedirectResponse(f"/incidents/{ref}/postmortem", status_code=303)


@router.post("/incidents/{ref}/postmortem/finalize", dependencies=[Depends(require_csrf)])
async def postmortem_finalize(
    ref: str, container: ContainerDep, who: WebResponder, confirm: str = Form(default="")
) -> RedirectResponse:
    with web_errors():
        async with container.sessions.begin() as session:
            iid = await incidents_routes.resolve_id(session, ref)
            existing = await container.postmortems.get(session, iid)
            if confirm == "true" and existing is not None:
                await container.postmortems.edit(
                    session, iid, existing.markdown, who.actor, finalize=True
                )
    return RedirectResponse(f"/incidents/{ref}/postmortem", status_code=303)


# ------------------------------------------------------------------- runbooks


@router.get("/runbooks", response_class=HTMLResponse)
async def runbooks_list(
    request: Request, container: ContainerDep, who: WebViewer, csrf_token: CsrfToken
) -> HTMLResponse:
    runbooks = await investigations_routes.list_runbooks(container, _identity(who))
    return render(request, "runbooks.html", identity=who, csrf_token=csrf_token, runbooks=runbooks)


# ---------------------------------------------------------------------- audit


@router.get("/audit", response_class=HTMLResponse)
async def audit_list(
    request: Request, container: ContainerDep, who: WebApprover, csrf_token: CsrfToken
) -> HTMLResponse:
    from sentinel.api.routes import admin as admin_routes

    events = await admin_routes.list_audit(container, _identity(who), None, None, 200)
    return render(request, "audit.html", identity=who, csrf_token=csrf_token, events=events)
