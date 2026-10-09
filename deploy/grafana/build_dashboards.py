"""Generate provisioned Grafana dashboards.

Run: uv run python deploy/grafana/build_dashboards.py
The JSON output is committed. tests/policy/test_monitoring_config.py fails if it is stale.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

OUT = Path(__file__).parent / "dashboards"
PROM = {"type": "prometheus", "uid": "prometheus"}
LOKI = {"type": "loki", "uid": "loki"}


class Layout:
    def __init__(self) -> None:
        self.panels: list[dict[str, Any]] = []
        self.y = 0
        self.x = 0
        self.row_h = 0

    def _place(self, w: int, h: int) -> dict[str, int]:
        if self.x + w > 24:
            self.y += self.row_h
            self.x, self.row_h = 0, 0
        pos = {"x": self.x, "y": self.y, "w": w, "h": h}
        self.x += w
        self.row_h = max(self.row_h, h)
        return pos

    def row(self, title: str) -> None:
        if self.x:
            self.y += self.row_h
            self.x, self.row_h = 0, 0
        self.panels.append(
            {
                "type": "row",
                "title": title,
                "collapsed": False,
                "gridPos": {"x": 0, "y": self.y, "w": 24, "h": 1},
                "id": len(self.panels) + 1,
                "panels": [],
            }
        )
        self.y += 1

    def add(self, panel: dict[str, Any], w: int, h: int) -> None:
        panel["gridPos"] = self._place(w, h)
        panel["id"] = len(self.panels) + 1
        self.panels.append(panel)


def ts(
    title: str,
    targets: list[tuple[str, str]],
    unit: str = "short",
    thresholds: list[tuple[str, float | None]] | None = None,
    max_: float | None = None,
) -> dict[str, Any]:
    steps = [{"color": c, "value": v} for c, v in (thresholds or [("green", None)])]
    defaults: dict[str, Any] = {
        "unit": unit,
        "custom": {
            "lineWidth": 2,
            "fillOpacity": 8,
            "showPoints": "never",
            "thresholdsStyle": {"mode": "line" if thresholds else "off"},
        },
        "thresholds": {"mode": "absolute", "steps": steps},
    }
    if max_ is not None:
        defaults["max"] = max_
    return {
        "type": "timeseries",
        "title": title,
        "datasource": PROM,
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {
            "legend": {"displayMode": "list", "placement": "bottom"},
            "tooltip": {"mode": "multi"},
        },
        "targets": [
            {"refId": chr(65 + i), "datasource": PROM, "expr": e, "legendFormat": lf}
            for i, (e, lf) in enumerate(targets)
        ],
    }


def stat(
    title: str, expr: str, unit: str, thresholds: list[tuple[str, float | None]], decimals: int = 2
) -> dict[str, Any]:
    return {
        "type": "stat",
        "title": title,
        "datasource": PROM,
        "fieldConfig": {
            "defaults": {
                "unit": unit,
                "decimals": decimals,
                "thresholds": {
                    "mode": "absolute",
                    "steps": [{"color": c, "value": v} for c, v in thresholds],
                },
            },
            "overrides": [],
        },
        "options": {
            "colorMode": "background",
            "graphMode": "area",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
        },
        "targets": [{"refId": "A", "datasource": PROM, "expr": expr}],
    }


def shop_api_dashboard() -> dict[str, Any]:
    svc = 'service="$service"'
    lay = Layout()
    lay.row("SLOs")
    lay.add(
        stat(
            "Availability (error ratio, 2m)",
            f"service:http_error_ratio:rate2m{{{svc}}}",
            "percentunit",
            [("green", None), ("orange", 0.005), ("red", 0.05)],
        ),
        6,
        4,
    )
    lay.add(
        stat(
            "Burn rate (30s)",
            f"service:slo_burn_rate:rate30s{{{svc}}}",
            "x",
            [("green", None), ("orange", 1), ("red", 10)],
            1,
        ),
        6,
        4,
    )
    lay.add(
        stat(
            "p95 latency (1m)",
            f"service:http_latency_p95:rate1m{{{svc}}}",
            "s",
            [("green", None), ("red", 0.3)],
            3,
        ),
        6,
        4,
    )
    lay.add(
        stat(
            "Throughput",
            f"service:http_requests:rate30s{{{svc}}}",
            "reqps",
            [("red", None), ("green", 1)],
            1,
        ),
        6,
        4,
    )

    lay.row("Traffic (RED)")
    lay.add(
        ts(
            "Request rate by status",
            [
                (
                    f'sum by (code) (rate(http_requests_total{{job="shop-api",{svc}}}[30s]))',
                    "{{code}}",
                ),
            ],
            "reqps",
        ),
        12,
        8,
    )
    lay.add(
        ts(
            "Error ratio vs SLO budget",
            [
                (f"service:http_error_ratio:rate30s{{{svc}}}", "30s"),
                (f"service:http_error_ratio:rate2m{{{svc}}}", "2m"),
            ],
            "percentunit",
            [("green", None), ("orange", 0.005), ("red", 0.05)],
        ),
        12,
        8,
    )
    lay.add(
        ts(
            "Latency percentiles",
            [
                (
                    f"histogram_quantile({q}, sum by (le) "
                    f"(rate(http_request_duration_seconds_bucket"
                    f'{{job="shop-api",{svc}}}[1m])))',
                    f"p{int(q * 100)}",
                )
                for q in (0.5, 0.95, 0.99)
            ],
            "s",
            [("green", None), ("red", 0.3)],
        ),
        12,
        8,
    )
    lay.add(
        ts(
            "Errors by version",
            [
                (
                    "sum by (version) (rate(http_requests_total"
                    f'{{job="shop-api",{svc},code=~"5.."}}[30s]))',
                    "{{version}}",
                ),
            ],
            "reqps",
        ),
        12,
        8,
    )

    lay.row("Saturation & stability")
    lay.add(
        ts(
            "Memory vs limit (per replica)",
            [
                (
                    f"fleet_container_memory_usage_bytes{{{svc}}}"
                    f" / fleet_container_memory_limit_bytes"
                    f"{{{svc}}}",
                    "replica {{replica}}",
                ),
            ],
            "percentunit",
            [("green", None), ("red", 0.8)],
            1,
        ),
        8,
        8,
    )
    lay.add(
        ts(
            "CPU vs quota (per replica)",
            [
                (
                    f"rate(fleet_container_cpu_usage_seconds_total{{{svc}}}[1m]) / "
                    f"fleet_container_cpu_limit_cores{{{svc}}}",
                    "replica {{replica}}",
                ),
            ],
            "percentunit",
            [("green", None), ("red", 0.9)],
            1,
        ),
        8,
        8,
    )
    lay.add(
        ts(
            "Restarts & replicas",
            [
                (f"fleet_container_restart_count{{{svc}}}", "restarts r{{replica}}"),
                (f"service:replicas_running:sum{{{svc}}}", "running"),
                (f"fleet_desired_replicas{{{svc}}}", "desired"),
            ],
        ),
        8,
        8,
    )

    lay.row("Changes & logs")
    lay.add(
        {
            "type": "table",
            "title": "Deployed release",
            "datasource": PROM,
            "targets": [
                {
                    "refId": "A",
                    "datasource": PROM,
                    "format": "table",
                    "instant": True,
                    "expr": f"fleet_deployment_info{{{svc}}}",
                }
            ],
            "transformations": [
                {
                    "id": "organize",
                    "options": {
                        "excludeByName": {
                            "Time": True,
                            "Value": True,
                            "__name__": True,
                            "job": True,
                            "instance": True,
                        }
                    },
                }
            ],
        },
        8,
        8,
    )
    lay.add(
        {
            "type": "logs",
            "title": "Error logs",
            "datasource": LOKI,
            "options": {"showTime": True, "wrapLogMessage": True, "sortOrder": "Descending"},
            "targets": [
                {
                    "refId": "A",
                    "datasource": LOKI,
                    "expr": f'{{{svc}}} | json | level=~"error|critical|warning"',
                }
            ],
        },
        16,
        8,
    )

    return {
        "uid": "sentinel-shop-api",
        "title": "Sentinel / shop-api service",
        "tags": ["sentinel", "slo"],
        "timezone": "browser",
        "schemaVersion": 41,
        "version": 1,
        "refresh": "5s",
        "time": {"from": "now-30m", "to": "now"},
        "annotations": {
            "list": [
                {
                    "name": "Deployments",
                    "datasource": PROM,
                    "enable": True,
                    "iconColor": "purple",
                    "expr": f"changes(fleet_last_deployment_timestamp_seconds{{{svc}}}[30s]) > 0",
                    "step": "5s",
                    "titleFormat": "Deployment",
                    "textFormat": "{{service}}",
                }
            ]
        },
        "templating": {
            "list": [
                {
                    "name": "service",
                    "type": "query",
                    "datasource": PROM,
                    "query": {
                        "query": "label_values(fleet_desired_replicas, service)",
                        "refId": "svc",
                    },
                    "current": {"text": "shop-api", "value": "shop-api"},
                    "refresh": 1,
                }
            ]
        },
        "panels": lay.panels,
    }


def render() -> dict[str, str]:
    return {"shop-api.json": json.dumps(shop_api_dashboard(), indent=2, sort_keys=True) + "\n"}


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, content in render().items():
        (OUT / name).write_text(content)
        print(f"wrote {OUT / name}")


if __name__ == "__main__":
    main()
