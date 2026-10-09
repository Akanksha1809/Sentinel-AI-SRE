"""Prometheus instrumentation for Sentinel itself."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram


class Metrics:
    def __init__(self) -> None:
        r = self.registry = CollectorRegistry(auto_describe=True)
        self.http_requests = Counter(
            "sentinel_http_requests_total",
            "HTTP requests.",
            ["method", "route", "code"],
            registry=r,
        )
        self.http_latency = Histogram(
            "sentinel_http_request_duration_seconds",
            "HTTP request latency.",
            ["method", "route"],
            registry=r,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
        )
        self.alerts_received = Counter(
            "sentinel_alerts_received_total",
            "Alerts received from Alertmanager.",
            ["status"],
            registry=r,
        )
        self.webhook_rejected = Counter(
            "sentinel_webhook_rejected_total",
            "Rejected webhook deliveries.",
            ["reason"],
            registry=r,
        )
        self.incidents = Counter(
            "sentinel_incidents_total", "Incident lifecycle outcomes.", ["outcome"], registry=r
        )
        self.deployments = Counter(
            "sentinel_deployments_recorded_total",
            "Deployment events recorded.",
            ["created"],
            registry=r,
        )
        self.jobs = Gauge(
            "sentinel_jobs", "Jobs by status (refreshed by the worker).", ["status"], registry=r
        )
        self.evidence_collections = Counter(
            "sentinel_evidence_collections_total",
            "Evidence collections by status.",
            ["status"],
            registry=r,
        )
        self.evidence_seconds = Histogram(
            "sentinel_evidence_collection_seconds",
            "Evidence collection duration.",
            registry=r,
            buckets=(0.5, 1, 2, 5, 10, 20, 30, 60),
        )
        self.investigations = Counter(
            "sentinel_investigations_total",
            "Investigations by provider and outcome.",
            ["provider", "outcome"],
            registry=r,
        )
        self.investigation_seconds = Histogram(
            "sentinel_investigation_seconds",
            "Investigation latency (provider call).",
            ["provider"],
            registry=r,
            buckets=(0.01, 0.1, 1, 5, 15, 30, 60, 120, 240, 300),
        )
        self.build = Gauge("sentinel_build_info", "Build info.", ["version"], registry=r)
