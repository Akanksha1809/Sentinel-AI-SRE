"""VerificationService's pure check-evaluation and consecutive-sample logic.

Uses a fake MetricsSource (no Prometheus) and a real DB-free VerificationService:
only `_evaluate_check` / `_sample` are exercised here. The full persisted flow
(action -> verifying -> succeeded/verification_failed -> incident resolved) is
covered against real Postgres in tests/integration/test_remediation_flow.py.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sentinel.evidence.clients import QueryError
from sentinel.evidence.model import Point, Series
from sentinel.ids import ManualClock
from sentinel.remediation.runbooks import Check
from sentinel.remediation.verifier import VerificationService, render_signal_query

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)


class FakeMetrics:
    def __init__(self) -> None:
        self.responses: list[list[Series] | Exception] = []
        self.queries: list[str] = []

    def push(self, value: float | Exception | None) -> None:
        if isinstance(value, Exception):
            self.responses.append(value)
        elif value is None:
            self.responses.append([])
        else:
            self.responses.append([Series({}, (Point(NOW.timestamp(), value),))])

    async def query_instant(self, query: str, at: datetime) -> list[Series]:
        self.queries.append(query)
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    async def query_range(self, *a: object, **k: object) -> list[Series]:
        raise NotImplementedError


def service(metrics: FakeMetrics) -> VerificationService:
    return VerificationService(
        sessions=None,
        clock=ManualClock(NOW),
        incidents=None,  # type: ignore[arg-type]
        catalog=None,
        audit=None,
        metrics=metrics,
    )  # type: ignore[arg-type]


class TestRenderSignalQuery:
    def test_all_signals_render_without_error(self) -> None:
        for signal in (
            "error_ratio",
            "latency_p95",
            "memory_ratio",
            "replicas_ready_ratio",
            "restarts_in_window",
        ):
            q = render_signal_query(signal, "shop-api", 60)  # type: ignore[arg-type]
            assert "shop-api" in q

    def test_unsafe_service_name_rejected(self) -> None:
        from sentinel.evidence.templates import UnsafeLabelError

        with pytest.raises(UnsafeLabelError):
            render_signal_query("error_ratio", 'shop-api"} or vector(1', 60)

    def test_replicas_ready_ratio_matches_only_on_service(self) -> None:
        """Regression (found live): `fleet_desired_replicas` is a raw scrape (still
        carrying job/instance labels), while the recording rule on the left has
        already dropped everything but `service`. Without `on(service)`, PromQL's
        default one-to-one match requires identical label sets and silently returns
        no result — every verification sample read "no data" and failed. The same
        fix was already applied to the `ShopApiReplicasUnavailable` alert rule in
        deploy/prometheus/rules/alerts.yml; it just hadn't been applied here too."""
        q = render_signal_query("replicas_ready_ratio", "shop-api", 60)
        assert "on(service)" in q


class TestEvaluateCheck:
    async def test_passing_check(self) -> None:
        m = FakeMetrics()
        m.push(0.001)
        svc = service(m)
        check = Check(signal="error_ratio", op="lt", value=0.01)
        result = await svc._evaluate_check(check, "shop-api", 60)
        assert result["passed"] is True
        assert result["observed"] == pytest.approx(0.001)

    async def test_failing_check(self) -> None:
        m = FakeMetrics()
        m.push(0.5)
        svc = service(m)
        check = Check(signal="error_ratio", op="lt", value=0.01)
        result = await svc._evaluate_check(check, "shop-api", 60)
        assert result["passed"] is False

    async def test_no_data_counts_as_failed(self) -> None:
        m = FakeMetrics()
        m.push(None)
        svc = service(m)
        check = Check(signal="error_ratio", op="lt", value=0.01)
        result = await svc._evaluate_check(check, "shop-api", 60)
        assert result["passed"] is False
        assert result["observed"] is None
        assert "no data" in result["error"]

    async def test_query_error_counts_as_failed(self) -> None:
        m = FakeMetrics()
        m.push(QueryError("prometheus unreachable"))
        svc = service(m)
        check = Check(signal="error_ratio", op="lt", value=0.01)
        result = await svc._evaluate_check(check, "shop-api", 60)
        assert result["passed"] is False
        assert "unreachable" in result["error"]

    async def test_eq_op_used_by_restarts_in_window(self) -> None:
        m = FakeMetrics()
        m.push(0.0)
        svc = service(m)
        check = Check(signal="restarts_in_window", op="eq", value=0)
        result = await svc._evaluate_check(check, "shop-api", 90)
        assert result["passed"] is True
        assert "[90s]" in m.queries[0]

    async def test_sample_fails_if_any_check_fails(self) -> None:
        m = FakeMetrics()
        m.push(0.001)  # error_ratio: pass
        m.push(1.0)  # replicas_ready_ratio: fail (target gte 1.0 would pass actually)
        svc = service(m)
        checks = (
            Check(signal="error_ratio", op="lt", value=0.01),
            Check(signal="replicas_ready_ratio", op="gte", value=2.0),
        )
        sample = await svc._sample(checks, "shop-api", 60, NOW)
        assert sample["passed"] is False
        assert sample["checks"][0]["passed"] is True
        assert sample["checks"][1]["passed"] is False
