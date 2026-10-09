"""Fleet telemetry: periodic polling, Prometheus collector, http_sd targets.

Polling runs in the background, so a Prometheus scrape never blocks on the Docker API.
`fleet_container_restart_count` is a gauge taken from Docker's RestartCount. It
resets when a container is recreated, so alerts use `delta()` or `changes()` on it,
never `rate()`.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime

from prometheus_client import Counter
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily
from prometheus_client.registry import Collector, CollectorRegistry

from actuator.fleet import FleetManager
from actuator.runtime import ContainerInfo, ContainerStats

log = logging.getLogger("actuator.telemetry")


@dataclass
class ServiceObservation:
    containers: list[ContainerInfo] = field(default_factory=list)
    stats: dict[str, ContainerStats] = field(default_factory=dict)
    observed_at: float = 0.0


class FleetObserver:
    def __init__(self, fleet: FleetManager, registry: CollectorRegistry) -> None:
        self._fleet = fleet
        self.cache: dict[str, ServiceObservation] = {}
        self.poll_errors = Counter(
            "fleet_poll_errors_total", "Failed fleet polls.", registry=registry
        )

    async def poll_once(self) -> None:
        for service in self._fleet.catalog.services:
            try:
                snap = await self._fleet.snapshot(service)
                stats: dict[str, ContainerStats] = {}
                for c in snap.containers:
                    if c.status == "running":
                        try:
                            stats[c.id] = await asyncio.to_thread(self._fleet.runtime.stats, c.id)
                        except Exception:
                            log.debug("stats failed", extra={"container": c.name}, exc_info=True)
                self.cache[service] = ServiceObservation(snap.containers, stats, time.time())
            except Exception:
                self.poll_errors.inc()
                log.warning("fleet poll failed", extra={"service": service}, exc_info=True)

    async def run(self, interval_s: float) -> None:
        while True:
            await self.poll_once()
            await asyncio.sleep(interval_s)

    def sd_targets(self, port_for: dict[str, int]) -> list[dict[str, object]]:
        targets: list[dict[str, object]] = []
        for service, obs in self.cache.items():
            for c in obs.containers:
                if c.status != "running":
                    continue
                targets.append(
                    {
                        "targets": [f"{c.name}:{port_for[service]}"],
                        "labels": {
                            "service": service,
                            "replica": str(c.replica),
                            "version": c.version,
                            "config_revision": c.config_revision,
                        },
                    }
                )
        return targets


class FleetCollector(Collector):
    def __init__(self, observer: FleetObserver, fleet: FleetManager) -> None:
        self._obs = observer
        self._fleet = fleet

    def collect(self) -> Iterator[GaugeMetricFamily | CounterMetricFamily]:
        sr = ["service", "replica"]
        desired = GaugeMetricFamily(
            "fleet_desired_replicas", "Desired replicas.", labels=["service"]
        )
        running = GaugeMetricFamily(
            "fleet_container_running",
            "1 if the replica is running.",
            labels=[*sr, "version", "config_revision", "status"],
        )
        restarts = GaugeMetricFamily(
            "fleet_container_restart_count", "Docker RestartCount (resets on recreate).", labels=sr
        )
        mem = GaugeMetricFamily(
            "fleet_container_memory_usage_bytes",
            "Container memory usage excluding inactive file cache.",
            labels=sr,
        )
        mem_limit = GaugeMetricFamily(
            "fleet_container_memory_limit_bytes", "Container memory limit.", labels=sr
        )
        cpu = CounterMetricFamily(
            "fleet_container_cpu_usage_seconds", "Container CPU time consumed.", labels=sr
        )
        cpu_limit = GaugeMetricFamily(
            "fleet_container_cpu_limit_cores", "CPU quota in cores.", labels=sr
        )
        info = GaugeMetricFamily(
            "fleet_deployment_info",
            "Currently deployed release (value 1).",
            labels=["service", "version", "config_revision"],
        )
        last_deploy = GaugeMetricFamily(
            "fleet_last_deployment_timestamp_seconds",
            "Unix time of the last deployment.",
            labels=["service"],
        )
        age = GaugeMetricFamily(
            "fleet_observation_age_seconds", "Age of the cached fleet state.", labels=["service"]
        )

        now = time.time()
        for service, obs in self._obs.cache.items():
            desired.add_metric([service], self._fleet.desired_replicas(service))
            age.add_metric([service], now - obs.observed_at)
            if obs.containers:
                head = obs.containers[0]
                info.add_metric([service, head.version, head.config_revision], 1)
            for c in obs.containers:
                labels = [service, str(c.replica)]
                running.add_metric(
                    [*labels, c.version, c.config_revision, c.status],
                    1 if c.status == "running" else 0,
                )
                restarts.add_metric(labels, c.restart_count)
                st = obs.stats.get(c.id)
                if st is not None:
                    mem.add_metric(labels, st.memory_usage_bytes)
                    mem_limit.add_metric(labels, st.memory_limit_bytes)
                    cpu.add_metric(labels, st.cpu_usage_seconds)
                    cpu_limit.add_metric(labels, st.cpu_limit_cores)
        latest: dict[str, float] = {}
        for event in self._fleet.history:
            ts = _parse_ts(event.deployed_at)
            if ts is not None:
                latest[event.service] = max(ts, latest.get(event.service, 0.0))
        for service, ts in latest.items():
            last_deploy.add_metric([service], ts)
        yield from (
            desired,
            running,
            restarts,
            mem,
            mem_limit,
            cpu,
            cpu_limit,
            info,
            last_deploy,
            age,
        )


def _parse_ts(value: str) -> float | None:
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None
