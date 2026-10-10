"""RFC 9457 problem+json error responses."""

from __future__ import annotations

import html
from collections.abc import Mapping
from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy.orm.exc import StaleDataError
from starlette.exceptions import HTTPException

from sentinel.domain.actions import InvalidActionTransitionError
from sentinel.domain.incidents import InvalidTransitionError
from sentinel.incidents.service import IncidentNotFoundError
from sentinel.observability.context import correlation_id_var
from sentinel.remediation.runbooks import ParameterError
from sentinel.remediation.service import (
    ActionExpiredError,
    ActionLimitExceededError,
    ActionNotFoundError,
    RunbookChangedError,
)
from sentinel.reports.service import PostmortemFinalizedError, PostmortemNotFoundError
from sentinel.web.deps import LoginRequiredError

log = structlog.get_logger("sentinel.errors")
_TITLES = {
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    409: "Conflict",
    413: "Payload Too Large",
    422: "Unprocessable Content",
    500: "Internal Server Error",
    503: "Service Unavailable",
}


def problem(
    status: int, detail: str, headers: Mapping[str, str] | None = None, **extra: Any
) -> JSONResponse:
    body = {
        "type": "about:blank",
        "title": _TITLES.get(status, "Error"),
        "status": status,
        "detail": detail,
        "correlation_id": correlation_id_var.get(),
        **extra,
    }
    return JSONResponse(
        body, status_code=status, headers=headers, media_type="application/problem+json"
    )


def _html_error(status: int, detail: str) -> HTMLResponse:
    title = _TITLES.get(status, "Error")
    return HTMLResponse(
        f"<!doctype html><html><head><meta charset='utf-8'><title>{title}</title></head>"
        f"<body style='font-family:system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem'>"
        f"<h1>{status} {title}</h1><p>{detail}</p><p><a href='/'>Back to incidents</a></p>"
        f"</body></html>",
        status_code=status,
    )


def install(app: FastAPI) -> None:
    @app.exception_handler(LoginRequiredError)
    async def _login_required(request: Request, _: LoginRequiredError) -> RedirectResponse:
        return RedirectResponse(f"/login?next={request.url.path}", status_code=303)

    @app.exception_handler(HTTPException)
    async def _http(request: Request, exc: HTTPException) -> JSONResponse | HTMLResponse:
        if request.url.path.startswith("/api/"):
            return problem(exc.status_code, str(exc.detail), headers=exc.headers)
        return _html_error(exc.status_code, html.escape(str(exc.detail)))

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]} for e in exc.errors()
        ][:20]
        return problem(422, "request validation failed", errors=errors)

    @app.exception_handler(IncidentNotFoundError)
    async def _not_found(_: Request, exc: IncidentNotFoundError) -> JSONResponse:
        return problem(404, f"incident {exc} not found")

    @app.exception_handler(InvalidTransitionError)
    async def _transition(_: Request, exc: InvalidTransitionError) -> JSONResponse:
        return problem(409, str(exc), current_status=exc.current.value)

    @app.exception_handler(StaleDataError)
    async def _stale(_: Request, exc: StaleDataError) -> JSONResponse:
        return problem(409, "incident was modified concurrently; retry")

    @app.exception_handler(ActionNotFoundError)
    async def _action_not_found(_: Request, exc: ActionNotFoundError) -> JSONResponse:
        return problem(404, f"action request {exc} not found")

    @app.exception_handler(InvalidActionTransitionError)
    async def _action_transition(_: Request, exc: InvalidActionTransitionError) -> JSONResponse:
        return problem(409, str(exc), current_status=exc.current.value)

    @app.exception_handler(RunbookChangedError)
    async def _runbook_changed(_: Request, exc: RunbookChangedError) -> JSONResponse:
        return problem(409, str(exc))

    @app.exception_handler(ActionExpiredError)
    async def _action_expired(_: Request, exc: ActionExpiredError) -> JSONResponse:
        return problem(409, str(exc))

    @app.exception_handler(ActionLimitExceededError)
    async def _action_limited(_: Request, exc: ActionLimitExceededError) -> JSONResponse:
        return problem(429, str(exc))

    @app.exception_handler(ParameterError)
    async def _bad_parameters(_: Request, exc: ParameterError) -> JSONResponse:
        return problem(422, str(exc))

    @app.exception_handler(PostmortemNotFoundError)
    async def _postmortem_not_found(_: Request, exc: PostmortemNotFoundError) -> JSONResponse:
        return problem(404, f"no postmortem draft exists yet for incident {exc}")

    @app.exception_handler(PostmortemFinalizedError)
    async def _postmortem_finalized(_: Request, exc: PostmortemFinalizedError) -> JSONResponse:
        return problem(409, str(exc))

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error")
        return problem(500, "internal error")
