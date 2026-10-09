"""Request-scoped context shared by logging, audit and persistence."""

from __future__ import annotations

from contextvars import ContextVar

correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)
