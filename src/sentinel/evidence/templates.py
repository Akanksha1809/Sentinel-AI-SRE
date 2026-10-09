"""Code-owned query templates (threat model T7).

Only these queries are ever executed. The single variable, the service name, is
validated against a strict pattern *and* escaped for PromQL/LogQL string literals.
Nothing from the LLM or alert payloads becomes query text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_SERVICE = re.compile(r"^[a-zA-Z0-9_.:-]{1,64}$")


class UnsafeLabelError(ValueError):
    pass


def label_value(value: str) -> str:
    """Validate and escape a value for use inside a "..." label matcher."""
    if not _SERVICE.fullmatch(value):
        raise UnsafeLabelError(f"refusing to query with label value {value!r}")
    return value.replace("\\", "\\\\").replace('"', '\\"')


@dataclass(frozen=True)
class MetricTemplate:
    ref: str
    title: str
    promql: str  # uses {svc}
    unit: str  # percent | seconds | ratio | count | rps
    primary_for: frozenset[str]
    step_min_delta: float  # minimum absolute change for a step to be significant
    group_by: str | None = None  # label the query aggregates by (for per-series stats)

    def render(self, service: str) -> str:
        return self.promql.format(svc=label_value(service))


_ERR = 'code=~"5.."'
METRICS: tuple[MetricTemplate, ...] = (
    MetricTemplate(
        "metric.error_ratio",
        "HTTP 5xx error ratio",
        'service:http_error_ratio:rate30s{{service="{svc}"}}',
        "percent",
        frozenset({"ShopApiHighErrorBurnRate"}),
        0.02,
    ),
    MetricTemplate(
        "metric.error_ratio_by_version",
        "HTTP 5xx error ratio by version",
        "sum by (version) (rate(http_requests_total"
        f'{{{{job="shop-api",service="{{svc}}",{_ERR}}}}}[1m]))'
        ' / sum by (version) (rate(http_requests_total{{job="shop-api",service="{svc}"}}[1m]))',
        "percent",
        frozenset({"ShopApiHighErrorBurnRate"}),
        0.05,
        group_by="version",
    ),
    MetricTemplate(
        "metric.request_rate",
        "Request throughput",
        'sum(rate(http_requests_total{{job="shop-api",service="{svc}"}}[1m]))',
        "rps",
        frozenset({"ShopApiDown"}),
        1.0,
    ),
    MetricTemplate(
        "metric.latency_p95",
        "p95 latency",
        'service:http_latency_p95:rate1m{{service="{svc}"}}',
        "seconds",
        frozenset({"ShopApiHighLatency"}),
        0.05,
    ),
    MetricTemplate(
        "metric.memory_ratio",
        "Container memory vs limit (per replica)",
        'max by (replica) (fleet_container_memory_usage_bytes{{service="{svc}"}}'
        ' / fleet_container_memory_limit_bytes{{service="{svc}"}})',
        "percent",
        frozenset({"ShopApiMemoryPressure"}),
        0.1,
        group_by="replica",
    ),
    MetricTemplate(
        "metric.cpu_ratio",
        "Container CPU vs quota (per replica)",
        'max by (replica) (rate(fleet_container_cpu_usage_seconds_total{{service="{svc}"}}[1m])'
        ' / fleet_container_cpu_limit_cores{{service="{svc}"}})',
        "percent",
        frozenset({"ShopApiHighCPU"}),
        0.2,
        group_by="replica",
    ),
    MetricTemplate(
        "metric.restarts",
        "Container restart count (per replica)",
        'max by (replica) (fleet_container_restart_count{{service="{svc}"}})',
        "count",
        frozenset({"ShopApiCrashLooping", "ShopApiReplicasUnavailable"}),
        1.0,
        group_by="replica",
    ),
    MetricTemplate(
        "metric.replicas_running",
        "Running replicas",
        'service:replicas_running:sum{{service="{svc}"}}',
        "count",
        frozenset({"ShopApiReplicasUnavailable", "ShopApiDown", "ShopApiCrashLooping"}),
        1.0,
    ),
)


@dataclass(frozen=True)
class LogTemplate:
    ref: str
    title: str
    logql: str
    limit: int
    primary_for: frozenset[str]

    def render(self, service: str) -> str:
        return self.logql.format(svc=label_value(service))


# Log queries select on the indexed `level` stream label (promoted by Alloy) instead of
# `| json | level=...`, which forces Loki to parse every line (it timed out over 2h windows).
ERROR_LOGS = LogTemplate(
    "log.errors",
    "Error and critical log lines",
    '{{service="{svc}", level=~"error|critical"}}',
    200,
    frozenset({"ShopApiHighErrorBurnRate", "ShopApiCrashLooping", "ShopApiDown"}),
)
WARNING_LOGS = LogTemplate(
    "log.warnings",
    "Warning log lines (includes 5xx access logs and chaos markers)",
    '{{service="{svc}", level="warning"}}',
    100,
    frozenset({"ShopApiMemoryPressure", "ShopApiHighLatency", "ShopApiHighCPU"}),
)
ERROR_LOG_RATE_BY_VERSION = (
    "sum by (version, config_revision) "
    '(count_over_time({{service="{svc}", level=~"error|critical"}}[1m]))'
)

# Instant query: 5xx responses per version over the incident window. `{window_s}` is an
# integer computed in code (never external input).
ERRORS_BY_VERSION = (
    'sum by (version) (increase(http_requests_total{{job="shop-api",service="{svc}",'
    'code=~"5.."}}[{window_s}s]))'
)
