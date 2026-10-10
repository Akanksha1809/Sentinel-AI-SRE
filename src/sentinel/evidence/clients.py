"""Prometheus and Loki HTTP clients: timeouts, bounded retries, response size caps.

Query strings only ever come from `evidence.templates` (code-owned), never from the
LLM or alert payloads.
"""

from __future__ import annotations

import asyncio
import json
import math
from datetime import datetime
from typing import Any, Protocol

import httpx

from sentinel.evidence.model import LogLine, Point, Series

MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MAX_SERIES = 50
MAX_POINTS_PER_SERIES = 2000
RETRIES = 2


class QueryError(RuntimeError):
    """A telemetry query failed (after retries) or returned an unusable response."""


class MetricsSource(Protocol):
    async def query_range(
        self, query: str, start: datetime, end: datetime, step_s: float
    ) -> list[Series]: ...

    async def query_instant(self, query: str, at: datetime) -> list[Series]: ...


class LogSource(Protocol):
    async def query_logs(
        self, query: str, start: datetime, end: datetime, limit: int
    ) -> list[LogLine]: ...

    async def query_log_metrics(
        self, query: str, start: datetime, end: datetime, step_s: float
    ) -> list[Series]: ...


class _RetryableError(QueryError):
    """Transient failure (5xx, 429, transport): worth retrying."""


async def _fetch(client: httpx.AsyncClient, url: str, params: dict[str, Any]) -> Any:
    try:
        async with client.stream("GET", url, params=params) as resp:
            if resp.status_code >= 500 or resp.status_code == 429:
                raise _RetryableError(f"HTTP {resp.status_code} from {url}")
            body = bytearray()
            async for chunk in resp.aiter_bytes():
                body.extend(chunk)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise QueryError(f"response from {url} exceeds {MAX_RESPONSE_BYTES} bytes")
            if resp.status_code >= 400:  # a bad query: retrying won't help
                detail = bytes(body[:300]).decode(errors="replace")
                raise QueryError(f"HTTP {resp.status_code} from {url}: {detail}")
    except httpx.TransportError as exc:
        raise _RetryableError(f"{type(exc).__name__} contacting {url}") from exc
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise QueryError(f"invalid JSON from {url}") from exc


async def _get_json(client: httpx.AsyncClient, url: str, params: dict[str, Any]) -> Any:
    for attempt in range(RETRIES + 1):
        try:
            return await _fetch(client, url, params)
        except _RetryableError:
            if attempt == RETRIES:
                raise
            await asyncio.sleep(0.5 * 2**attempt)
    raise AssertionError("unreachable")


def _parse_matrix(payload: Any) -> list[Series]:
    if not isinstance(payload, dict) or payload.get("status") != "success":
        raise QueryError(f"query failed: {str(payload)[:200]}")
    data = payload.get("data") or {}
    if data.get("resultType") not in ("matrix", "vector"):
        raise QueryError(f"unexpected result type {data.get('resultType')!r}")
    out: list[Series] = []
    for item in (data.get("result") or [])[:MAX_SERIES]:
        raw = item.get("values") or ([item["value"]] if "value" in item else [])
        # Prometheus emits "NaN"/"+Inf"/"-Inf" for samples with no underlying data
        # (e.g. histogram_quantile over an empty bucket). Postgres's JSON parser is
        # stricter than Python's and rejects those tokens outright, so they are
        # dropped here rather than failing evidence storage; a dropped point is
        # exactly as informative as the "no data" gap it actually represents.
        points = tuple(
            Point(float(ts), float(v))
            for ts, v in raw[-MAX_POINTS_PER_SERIES:]
            if math.isfinite(float(v))
        )
        out.append(Series({str(k): str(v) for k, v in (item.get("metric") or {}).items()}, points))
    return out


class PrometheusClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout_s: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout_s, transport=transport)

    async def query_range(
        self, query: str, start: datetime, end: datetime, step_s: float
    ) -> list[Series]:
        payload = await _get_json(
            self._client,
            "/api/v1/query_range",
            {
                "query": query,
                "start": start.timestamp(),
                "end": end.timestamp(),
                "step": f"{step_s:g}s",
                "timeout": "8s",
            },
        )
        return _parse_matrix(payload)

    async def query_instant(self, query: str, at: datetime) -> list[Series]:
        payload = await _get_json(
            self._client,
            "/api/v1/query",
            {
                "query": query,
                "time": at.timestamp(),
                "timeout": "8s",
            },
        )
        return _parse_matrix(payload)

    async def aclose(self) -> None:
        await self._client.aclose()


class LokiClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout_s: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout_s, transport=transport)

    async def query_logs(
        self, query: str, start: datetime, end: datetime, limit: int
    ) -> list[LogLine]:
        payload = await _get_json(
            self._client,
            "/loki/api/v1/query_range",
            {
                "query": query,
                "start": int(start.timestamp() * 1e9),
                "end": int(end.timestamp() * 1e9),
                "limit": min(limit, 500),
                "direction": "backward",
            },
        )
        if not isinstance(payload, dict) or payload.get("status") != "success":
            raise QueryError(f"loki query failed: {str(payload)[:200]}")
        data = payload.get("data") or {}
        if data.get("resultType") != "streams":
            raise QueryError(f"expected streams, got {data.get('resultType')!r}")
        lines = [
            LogLine(
                int(ts) / 1e9,
                {str(k): str(v) for k, v in stream.get("stream", {}).items()},
                str(line),
            )
            for stream in data.get("result") or []
            for ts, line in stream.get("values") or []
        ]
        lines.sort(key=lambda entry: entry.ts, reverse=True)
        return lines[:limit]

    async def query_log_metrics(
        self, query: str, start: datetime, end: datetime, step_s: float
    ) -> list[Series]:
        payload = await _get_json(
            self._client,
            "/loki/api/v1/query_range",
            {
                "query": query,
                "start": int(start.timestamp() * 1e9),
                "end": int(end.timestamp() * 1e9),
                "step": f"{step_s:g}s",
            },
        )
        return _parse_matrix(payload)

    async def aclose(self) -> None:
        await self._client.aclose()
