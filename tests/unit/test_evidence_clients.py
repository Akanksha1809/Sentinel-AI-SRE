"""Prometheus/Loki clients against mocked HTTP (respx)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import respx

from sentinel.evidence import clients
from sentinel.evidence.clients import LokiClient, PrometheusClient, QueryError

PROM = "http://prom.test"
LOKI = "http://loki.test"
END = datetime(2026, 10, 9, 12, 30, tzinfo=UTC)
START = END - timedelta(minutes=30)


@pytest.fixture(autouse=True)
def no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    async def instant(_: float) -> None:
        return None

    monkeypatch.setattr(clients.asyncio, "sleep", instant)


def matrix(*series: dict[str, Any]) -> dict[str, Any]:
    return {"status": "success", "data": {"resultType": "matrix", "result": list(series)}}


@respx.mock
async def test_query_range_parses_matrix_and_sends_params() -> None:
    route = respx.get(f"{PROM}/api/v1/query_range").mock(
        return_value=httpx.Response(
            200,
            json=matrix(
                {
                    "metric": {"service": "shop-api"},
                    "values": [[1.0, "0.1"], [16.0, "0.15"], [31.0, "0.2"]],
                }
            ),
        )
    )
    [s] = await PrometheusClient(PROM).query_range("up", START, END, 15)
    assert s.labels == {"service": "shop-api"}
    assert [p.ts for p in s.points] == [1.0, 16.0, 31.0]
    params = route.calls.last.request.url.params
    assert params["query"] == "up"
    assert params["step"] == "15s"


@respx.mock
async def test_non_finite_points_are_dropped_not_kept() -> None:
    """Regression: Prometheus emits "NaN"/"+Inf"/"-Inf" for samples with no real data
    (e.g. histogram_quantile over an empty bucket). Postgres's JSON parser rejects
    those tokens outright (unlike Python's), so a kept NaN used to crash evidence
    storage with `invalid input syntax for type json: Token "NaN" is invalid`
    (found live running Phase 6). They must be dropped at parse time, not kept."""
    respx.get(f"{PROM}/api/v1/query_range").mock(
        return_value=httpx.Response(
            200,
            json=matrix(
                {
                    "metric": {"service": "shop-api"},
                    "values": [
                        [1.0, "0.1"],
                        [16.0, "NaN"],
                        [24.0, "+Inf"],
                        [28.0, "-Inf"],
                        [31.0, "0.2"],
                    ],
                }
            ),
        )
    )
    [s] = await PrometheusClient(PROM).query_range("up", START, END, 15)
    assert [p.ts for p in s.points] == [1.0, 31.0]
    assert [p.value for p in s.points] == [0.1, 0.2]
    # Every surviving value must actually be JSON-serialisable the strict way Postgres
    # requires (Python's json module, unlike Postgres, would happily emit NaN/Infinity).
    json.dumps([p.value for p in s.points], allow_nan=False)


@respx.mock
async def test_retries_transient_failures_then_succeeds() -> None:
    route = respx.get(f"{PROM}/api/v1/query_range").mock(
        side_effect=[
            httpx.Response(503),
            httpx.ConnectError("refused"),
            httpx.Response(200, json=matrix()),
        ]
    )
    assert await PrometheusClient(PROM).query_range("up", START, END, 15) == []
    assert route.call_count == 3


@respx.mock
async def test_gives_up_after_bounded_retries() -> None:
    route = respx.get(f"{PROM}/api/v1/query_range").mock(return_value=httpx.Response(500))
    with pytest.raises(QueryError, match="HTTP 500"):
        await PrometheusClient(PROM).query_range("up", START, END, 15)
    assert route.call_count == clients.RETRIES + 1


@respx.mock
async def test_bad_query_is_not_retried() -> None:
    route = respx.get(f"{PROM}/api/v1/query_range").mock(
        return_value=httpx.Response(400, json={"status": "error", "error": "parse error"})
    )
    with pytest.raises(QueryError, match="HTTP 400"):
        await PrometheusClient(PROM).query_range("up{", START, END, 15)
    assert route.call_count == 1


@respx.mock
async def test_oversized_response_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clients, "MAX_RESPONSE_BYTES", 1000)
    respx.get(f"{PROM}/api/v1/query_range").mock(
        return_value=httpx.Response(200, content=b"{" + b" " * 5000 + b"}")
    )
    with pytest.raises(QueryError, match="exceeds"):
        await PrometheusClient(PROM).query_range("up", START, END, 15)


@respx.mock
async def test_series_count_is_capped() -> None:
    many = [{"metric": {"i": str(i)}, "values": [[1, "1"]]} for i in range(500)]
    respx.get(f"{PROM}/api/v1/query_range").mock(
        return_value=httpx.Response(200, json=matrix(*many))
    )
    result = await PrometheusClient(PROM).query_range("up", START, END, 15)
    assert len(result) == clients.MAX_SERIES


@respx.mock
async def test_prometheus_error_status_in_body() -> None:
    respx.get(f"{PROM}/api/v1/query").mock(
        return_value=httpx.Response(200, json={"status": "error", "error": "timeout"})
    )
    with pytest.raises(QueryError):
        await PrometheusClient(PROM).query_instant("up", END)


@respx.mock
async def test_loki_streams_sorted_newest_first_and_limited() -> None:
    respx.get(f"{LOKI}/loki/api/v1/query_range").mock(
        return_value=httpx.Response(
            200,
            json={
                "status": "success",
                "data": {
                    "resultType": "streams",
                    "result": [
                        {
                            "stream": {"container": "shop-api-1"},
                            "values": [["1000000000000", "a"], ["3000000000000", "c"]],
                        },
                        {"stream": {"container": "shop-api-2"}, "values": [["2000000000000", "b"]]},
                    ],
                },
            },
        )
    )
    lines = await LokiClient(LOKI).query_logs('{service="x"}', START, END, limit=2)
    assert [entry.line for entry in lines] == ["c", "b"]
    assert lines[0].labels == {"container": "shop-api-1"}


@respx.mock
async def test_loki_wrong_result_type() -> None:
    respx.get(f"{LOKI}/loki/api/v1/query_range").mock(
        return_value=httpx.Response(
            200, json={"status": "success", "data": {"resultType": "matrix", "result": []}}
        )
    )
    with pytest.raises(QueryError, match="expected streams"):
        await LokiClient(LOKI).query_logs('{service="x"}', START, END, limit=10)
