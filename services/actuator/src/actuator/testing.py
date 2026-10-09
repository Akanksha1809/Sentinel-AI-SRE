"""Test doubles shipped with the package so every test suite (and Sentinel's) can use them."""

from __future__ import annotations

import itertools

from actuator.runtime import (
    MANAGED_LABEL,
    SERVICE_LABEL,
    ContainerInfo,
    ContainerSpec,
    ContainerStats,
    NotManagedError,
)


class FakeRuntime:
    """In-memory ContainerRuntime with the same managed-label guarantees as DockerRuntime."""

    def __init__(self, images: set[str] | None = None) -> None:
        self.containers: dict[str, ContainerInfo] = {}
        self.specs: dict[str, ContainerSpec] = {}
        self.images = (
            images if images is not None else {"sentinel/shop-api:1.0.0", "sentinel/shop-api:1.1.0"}
        )
        self.mutations: list[tuple[str, str]] = []
        self._ids = itertools.count(1)

    def add_foreign(self, name: str, service: str = "shop-api") -> str:
        cid = f"foreign{next(self._ids)}"
        self.containers[cid] = ContainerInfo(cid, name, {SERVICE_LABEL: service}, "running")
        return cid

    def list_managed(self, service: str) -> list[ContainerInfo]:
        found = [
            c
            for c in self.containers.values()
            if c.labels.get(MANAGED_LABEL) == "true" and c.labels.get(SERVICE_LABEL) == service
        ]
        return sorted(found, key=lambda c: c.replica)

    def image_exists(self, image: str) -> bool:
        return image in self.images

    def _guard(self, cid: str) -> None:
        if self.containers[cid].labels.get(MANAGED_LABEL) != "true":
            raise NotManagedError(cid)

    def create_and_start(self, spec: ContainerSpec) -> ContainerInfo:
        if any(c.name == spec.name for c in self.containers.values()):
            raise RuntimeError(f"name conflict: {spec.name}")
        cid = f"c{next(self._ids)}"
        info = ContainerInfo(cid, spec.name, dict(spec.labels), "running")
        self.containers[cid] = info
        self.specs[cid] = spec
        self.mutations.append(("create", spec.name))
        return info

    def remove(self, container_id: str, stop_timeout_s: int = 10) -> None:
        self._guard(container_id)
        self.mutations.append(("remove", self.containers[container_id].name))
        del self.containers[container_id]
        self.specs.pop(container_id, None)

    def restart(self, container_id: str, timeout_s: int = 10) -> None:
        self._guard(container_id)
        self.mutations.append(("restart", self.containers[container_id].name))

    def stats(self, container_id: str) -> ContainerStats:
        return ContainerStats(64 * 2**20, 256 * 2**20, 12.5, 0.5)
