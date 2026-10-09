"""Structured JSON logging (structlog). Every line carries the request's correlation_id."""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from sentinel.observability.context import correlation_id_var


def _add_correlation_id(_: Any, __: str, event: dict[str, Any]) -> dict[str, Any]:
    cid = correlation_id_var.get()
    if cid and "correlation_id" not in event:
        event["correlation_id"] = cid
    return event


def configure_logging(level: str = "INFO", component: str = "sentinel") -> None:
    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True, key="ts"),
        _add_correlation_id,
        structlog.processors.format_exc_info,
    ]
    structlog.configure(
        processors=[*shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            lambda _l, _m, ev: {**ev, "component": component},
            structlog.processors.JSONRenderer(),
        ],
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # Route uvicorn through the same JSON pipeline; access logs come from our middleware.
    for name in ("uvicorn", "uvicorn.error"):
        logging.getLogger(name).handlers.clear()
        logging.getLogger(name).propagate = True
    logging.getLogger("uvicorn.access").disabled = True
