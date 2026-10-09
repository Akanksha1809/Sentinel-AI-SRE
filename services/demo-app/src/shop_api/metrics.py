"""Prometheus instrumentation.

`service`, `replica`, `version` and `config_revision` are attached by Prometheus as
target labels (from the actuator's http_sd). They are deliberately *not* metric
labels here, which avoids `exported_*` label clashes.
"""

from __future__ import annotations

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    PlatformCollector,
    ProcessCollector,
)
from prometheus_client.gc_collector import GCCollector

LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.3, 0.5, 0.75, 1.0, 2.5, 5.0)


class Metrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry(auto_describe=True)
        ProcessCollector(registry=self.registry)
        PlatformCollector(registry=self.registry)
        GCCollector(registry=self.registry)

        self.requests = Counter(
            "http_requests_total",
            "HTTP requests handled.",
            ["method", "route", "code"],
            registry=self.registry,
        )
        self.latency = Histogram(
            "http_request_duration_seconds",
            "HTTP request latency.",
            ["method", "route"],
            buckets=LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.in_progress = Gauge(
            "http_requests_in_progress", "In-flight HTTP requests.", registry=self.registry
        )
        self.checkouts = Counter(
            "shop_checkouts_total",
            "Checkout attempts by outcome.",
            ["outcome"],
            registry=self.registry,
        )
        self.app_info = Gauge(
            "shop_app_info",
            "Static build/config info (value is always 1).",
            ["app_version", "app_config_revision", "release_defect"],
            registry=self.registry,
        )
        self.chaos_active = Gauge(
            "shop_chaos_active",
            "1 while a chaos fault is active.",
            ["mode"],
            registry=self.registry,
        )
        self.chaos_memory = Gauge(
            "shop_chaos_memory_allocated_bytes",
            "Bytes held by memory chaos.",
            registry=self.registry,
        )
