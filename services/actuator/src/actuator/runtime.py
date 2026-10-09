"""Container runtime boundary.

`ContainerSpec` intentionally has no fields for mounts, commands, privileges,
devices or host namespaces. The Docker adapter applies a fixed hardening profile
to every container it creates. Every mutating call re-checks the
`sentinel.managed` label, so the actuator cannot touch containers it doesn't own,
even if a caller hands it a foreign ID.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from typing import Any, Protocol

MANAGED_LABEL = "sentinel.managed"
SERVICE_LABEL = "sentinel.service"
REPLICA_LABEL = "sentinel.replica"
VERSION_LABEL = "sentinel.version"
REVISION_LABEL = "sentinel.config_revision"
DEPLOYED_AT_LABEL = "sentinel.deployed_at"
DEPLOYED_BY_LABEL = "sentinel.deployed_by"


class NotManagedError(PermissionError):
    """Refused: the container is not managed by Sentinel."""


class RuntimeUnavailableError(RuntimeError):
    """The container runtime (socket proxy / daemon) could not be reached."""


@dataclass(frozen=True)
class ContainerSpec:
    name: str
    image: str
    env: dict[str, str]
    labels: dict[str, str]
    network: str
    aliases: tuple[str, ...]
    memory_mb: int
    cpus: float
    pids: int


@dataclass
class ContainerInfo:
    id: str
    name: str
    labels: dict[str, str]
    status: str  # created | running | restarting | exited | ...
    restart_count: int = 0
    started_at: str | None = None
    health: str | None = None

    @property
    def replica(self) -> int:
        return int(self.labels.get(REPLICA_LABEL, "0"))

    @property
    def version(self) -> str:
        return self.labels.get(VERSION_LABEL, "unknown")

    @property
    def config_revision(self) -> str:
        return self.labels.get(REVISION_LABEL, "unknown")


@dataclass
class ContainerStats:
    memory_usage_bytes: int
    memory_limit_bytes: int
    cpu_usage_seconds: float
    cpu_limit_cores: float
    extra: dict[str, Any] = field(default_factory=dict)


class ContainerRuntime(Protocol):
    def list_managed(self, service: str) -> list[ContainerInfo]: ...
    def image_exists(self, image: str) -> bool: ...
    def create_and_start(self, spec: ContainerSpec) -> ContainerInfo: ...
    def remove(self, container_id: str, stop_timeout_s: int = 10) -> None: ...
    def restart(self, container_id: str, timeout_s: int = 10) -> None: ...
    def stats(self, container_id: str) -> ContainerStats: ...


class DockerRuntime:
    """Docker Engine API adapter (talks to the restricted socket proxy, never the raw socket)."""

    def __init__(self, base_url: str, timeout_s: int, api_version: str = "auto") -> None:
        import docker  # imported lazily so unit tests never need a daemon

        self._docker = docker
        # An explicit api_version avoids any daemon call at construction (used by tests).
        self._api = docker.APIClient(base_url=base_url, version=api_version, timeout=timeout_s)

    # -- helpers ---------------------------------------------------------------
    def _inspect(self, container_id: str) -> dict[str, Any]:
        data: dict[str, Any] = self._api.inspect_container(container_id)
        return data

    def _ensure_managed(self, container_id: str) -> dict[str, Any]:
        attrs = self._inspect(container_id)
        labels = (attrs.get("Config") or {}).get("Labels") or {}
        if labels.get(MANAGED_LABEL) != "true":
            raise NotManagedError(f"container {container_id[:12]} is not sentinel-managed")
        return attrs

    @staticmethod
    def _to_info(attrs: dict[str, Any]) -> ContainerInfo:
        state = attrs.get("State") or {}
        health = (state.get("Health") or {}).get("Status")
        return ContainerInfo(
            id=attrs["Id"],
            name=attrs["Name"].lstrip("/"),
            labels=(attrs.get("Config") or {}).get("Labels") or {},
            status=state.get("Status", "unknown"),
            restart_count=int(attrs.get("RestartCount", 0)),
            started_at=state.get("StartedAt"),
            health=health,
        )

    # -- protocol --------------------------------------------------------------
    def list_managed(self, service: str) -> list[ContainerInfo]:
        summaries = self._api.containers(
            all=True, filters={"label": [f"{MANAGED_LABEL}=true", f"{SERVICE_LABEL}={service}"]}
        )
        infos = [self._to_info(self._inspect(s["Id"])) for s in summaries]
        return sorted(infos, key=lambda c: c.replica)

    def image_exists(self, image: str) -> bool:
        try:
            self._api.inspect_image(image)
        except self._docker.errors.ImageNotFound:
            return False
        return True

    def build_create_config(self, spec: ContainerSpec) -> dict[str, Any]:
        """The exact `POST /containers/create` body. Pure: no daemon call (used by guard tests)."""
        if spec.labels.get(MANAGED_LABEL) != "true":
            raise NotManagedError("refusing to create a container without the managed label")
        host_config = self._api.create_host_config(
            mem_limit=f"{spec.memory_mb}m",
            memswap_limit=f"{spec.memory_mb}m",  # no swap: the limit is a hard cap
            nano_cpus=int(spec.cpus * 1e9),
            pids_limit=spec.pids,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            read_only=True,
            tmpfs={"/tmp": "rw,noexec,nosuid,size=16m"},  # nosec B108 # noqa: S108
            restart_policy={"Name": "on-failure"},
            log_config={"Type": "json-file", "Config": {"max-size": "10m", "max-file": "2"}},
            init=True,
        )
        networking = self._api.create_networking_config(
            {spec.network: self._api.create_endpoint_config(aliases=list(spec.aliases))}
        )
        config: dict[str, Any] = self._api.create_container_config(
            image=spec.image,
            command=None,
            environment=spec.env,
            labels=spec.labels,
            host_config=host_config,
            networking_config=networking,
        )
        return config

    def create_and_start(self, spec: ContainerSpec) -> ContainerInfo:
        config = self.build_create_config(spec)
        created = self._api.create_container_from_config(config, name=spec.name)
        self._api.start(created["Id"])
        return self._to_info(self._inspect(created["Id"]))

    def remove(self, container_id: str, stop_timeout_s: int = 10) -> None:
        self._ensure_managed(container_id)
        # Already stopped or restarting is fine: the forced removal below is authoritative.
        with contextlib.suppress(self._docker.errors.APIError):
            self._api.stop(container_id, timeout=stop_timeout_s)
        self._api.remove_container(container_id, force=True)

    def restart(self, container_id: str, timeout_s: int = 10) -> None:
        self._ensure_managed(container_id)
        self._api.restart(container_id, timeout=timeout_s)

    def stats(self, container_id: str) -> ContainerStats:
        raw: dict[str, Any] = self._api.stats(container_id, stream=False, one_shot=True)
        mem = raw.get("memory_stats") or {}
        usage = int(mem.get("usage", 0))
        # Match `docker stats`: exclude reclaimable page cache (cgroup v2: inactive_file).
        inactive = int((mem.get("stats") or {}).get("inactive_file", 0))
        cpu = (raw.get("cpu_stats") or {}).get("cpu_usage") or {}
        attrs = self._inspect(container_id)
        nano = int(((attrs.get("HostConfig") or {}).get("NanoCpus")) or 0)
        return ContainerStats(
            memory_usage_bytes=max(usage - inactive, 0),
            memory_limit_bytes=int(mem.get("limit", 0)),
            cpu_usage_seconds=int(cpu.get("total_usage", 0)) / 1e9,
            cpu_limit_cores=nano / 1e9 if nano else 0.0,
        )
