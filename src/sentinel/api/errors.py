"""RFC 9457 problem+json error responses."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.orm.exc import StaleDataError
from starlette.exceptions import HTTPException

from sentinel.domain.incidents import InvalidTransitionError
from sentinel.incidents.service import IncidentNotFoundError
from sentinel.observability.context import correlation_id_var

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


def install(app: FastAPI) -> None:
    @app.exception_handler(HTTPException)
    async def _http(_: Request, exc: HTTPException) -> JSONResponse:
        return problem(exc.status_code, str(exc.detail), headers=exc.headers)

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

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error")
        return problem(500, "internal error")
