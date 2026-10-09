"""Fleet operations: deploy / rollback / restart / scale.

Each operation:
- validates the target against the release catalogue and replica bounds,
- is idempotent (it does nothing when the fleet is already in the requested state),
- supports dry-run (returns the plan and makes no runtime calls that mutate anything),
- holds a per-service lock, so concurrent requests cannot interleave.
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import SecretStr

from actuator.catalog import ReleaseCatalog, ServiceSpec, UnknownTargetError
from actuator.runtime import (
    DEPLOYED_AT_LABEL,
    DEPLOYED_BY_LABEL,
    MANAGED_LABEL,
    REPLICA_LABEL,
    REVISION_LABEL,
    SERVICE_LABEL,
    VERSION_LABEL,
    ContainerInfo,
    ContainerRuntime,
    ContainerSpec,
)

log = logging.getLogger("actuator.fleet")

ActionKind = Literal["deploy", "rollback", "restart", "scale", "reconcile"]


class BoundsError(ValueError):
    """Requested parameter outside allowed bounds."""


class PreconditionError(RuntimeError):
    """Operation cannot proceed in the current state (e.g. image not built)."""


@dataclass
class ActionResult:
    action: ActionKind
    service: str
    dry_run: bool
    changed: bool
    plan: list[str]
    before: dict[str, Any]
    after: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DeploymentEvent:
    service: str
    version: str
    config_revision: str
    previous_version: str | None
    previous_config_revision: str | None
    deployed_at: str
    deployed_by: str
    source: ActionKind
    change_ref: str | None = None


@dataclass
class FleetSnapshot:
    service: str
    desired_replicas: int
    version: str | None
    config_revision: str | None
    containers: list[ContainerInfo] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "desired_replicas": self.desired_replicas,
            "version": self.version,
            "config_revision": self.config_revision,
            "replicas": [
                {
                    "name": c.name,
                    "replica": c.replica,
                    "status": c.status,
                    "health": c.health,
                    "version": c.version,
                    "config_revision": c.config_revision,
                    "restart_count": c.restart_count,
                    "started_at": c.started_at,
                }
                for c in self.containers
            ],
        }


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


EventSink = Callable[[DeploymentEvent], Awaitable[None]]


class FleetManager:
    def __init__(
        self,
        catalog: ReleaseCatalog,
        runtime: ContainerRuntime,
        network: str,
        chaos_token: SecretStr | None,
        event_sink: EventSink | None = None,
        clock: Callable[[], str] = _now,
    ) -> None:
        self._catalog = catalog
        self._runtime = runtime
        self._network = network
        self._chaos_token = chaos_token
        self._event_sink = event_sink
        self._clock = clock
        self._locks: dict[str, asyncio.Lock] = {n: asyncio.Lock() for n in catalog.services}
        self._desired: dict[str, int] = {n: s.initial.replicas for n, s in catalog.services.items()}
        self.history: deque[DeploymentEvent] = deque(maxlen=200)

    # ---- queries -------------------------------------------------------------
    @property
    def catalog(self) -> ReleaseCatalog:
        return self._catalog

    @property
    def runtime(self) -> ContainerRuntime:
        return self._runtime

    async def _list(self, service: str) -> list[ContainerInfo]:
        return await asyncio.to_thread(self._runtime.list_managed, service)

    async def snapshot(self, service: str) -> FleetSnapshot:
        self._catalog.service(service)
        containers = await self._list(service)
        head = containers[0] if containers else None
        return FleetSnapshot(
            service=service,
            desired_replicas=self._desired[service],
            version=head.version if head else None,
            config_revision=head.config_revision if head else None,
            containers=containers,
        )

    def desired_replicas(self, service: str) -> int:
        return self._desired[service]

    # ---- spec construction ---------------------------------------------------
    def _spec(
        self, service: str, svc: ServiceSpec, replica: int, version: str, revision: str, actor: str
    ) -> ContainerSpec:
        env = {
            "SERVICE_NAME": service,
            "APP_VERSION": version,
            "CONFIG_REVISION": revision,
            "REPLICA": str(replica),
            **svc.config_revisions[revision],
        }
        if self._chaos_token is not None:
            env["CHAOS_TOKEN"] = self._chaos_token.get_secret_value()
        labels = {
            MANAGED_LABEL: "true",
            SERVICE_LABEL: service,
            REPLICA_LABEL: str(replica),
            VERSION_LABEL: version,
            REVISION_LABEL: revision,
            DEPLOYED_AT_LABEL: self._clock(),
            DEPLOYED_BY_LABEL: actor,
            "sentinel.logs": "true",
        }
        return ContainerSpec(
            name=f"{service}-{replica}",
            image=svc.image_for(version),
            env=env,
            labels=labels,
            network=self._network,
            aliases=(service,),
            memory_mb=svc.resources.memory_mb,
            cpus=svc.resources.cpus,
            pids=svc.resources.pids,
        )

    def _validate_target(self, svc: ServiceSpec, version: str, revision: str) -> None:
        if version not in svc.releases:
            raise UnknownTargetError(f"version {version!r} is not in the release catalogue")
        if revision not in svc.config_revisions:
            raise UnknownTargetError(f"config revision {revision!r} is not in the catalogue")

    async def _require_image(self, image: str) -> None:
        if not await asyncio.to_thread(self._runtime.image_exists, image):
            raise PreconditionError(f"image {image} is not available locally; run `make images`")

    # ---- operations ----------------------------------------------------------
    async def deploy(
        self,
        service: str,
        version: str,
        config_revision: str,
        *,
        actor: str,
        source: Literal["deploy", "rollback"] = "deploy",
        dry_run: bool = False,
        change_ref: str | None = None,
    ) -> ActionResult:
        svc = self._catalog.service(service)
        self._validate_target(svc, version, config_revision)
        async with self._locks[service]:
            before = await self.snapshot(service)
            by_replica = {c.replica: c for c in before.containers}
            plan: list[str] = []
            for i in range(1, self._desired[service] + 1):
                cur = by_replica.get(i)
                if cur and (cur.version, cur.config_revision) == (version, config_revision):
                    continue
                if cur:
                    plan.append(
                        f"replace {cur.name} ({cur.version}/{cur.config_revision}) "
                        f"with {version}/{config_revision}"
                    )
                else:
                    plan.append(f"create {service}-{i} at {version}/{config_revision}")
            if not plan:
                return ActionResult(
                    source, service, dry_run, False, ["already at target; no-op"], before.to_dict()
                )
            if dry_run:
                return ActionResult(source, service, True, False, plan, before.to_dict())

            await self._require_image(svc.image_for(version))
            for i in range(1, self._desired[service] + 1):
                cur = by_replica.get(i)
                if cur and (cur.version, cur.config_revision) == (version, config_revision):
                    continue
                if cur:
                    await asyncio.to_thread(self._runtime.remove, cur.id)
                spec = self._spec(service, svc, i, version, config_revision, actor)
                await asyncio.to_thread(self._runtime.create_and_start, spec)
                log.info(
                    "replica replaced",
                    extra={
                        "service": service,
                        "replica": i,
                        "version": version,
                        "revision": config_revision,
                    },
                )
            after = await self.snapshot(service)
            await self._record(
                DeploymentEvent(
                    service=service,
                    version=version,
                    config_revision=config_revision,
                    previous_version=before.version,
                    previous_config_revision=before.config_revision,
                    deployed_at=self._clock(),
                    deployed_by=actor,
                    source=source,
                    change_ref=change_ref,
                )
            )
            return ActionResult(
                source, service, False, True, plan, before.to_dict(), after.to_dict()
            )

    async def rollback(
        self,
        service: str,
        target_version: str,
        target_config_revision: str | None,
        *,
        actor: str,
        dry_run: bool = False,
    ) -> ActionResult:
        if target_config_revision is None:
            current = await self.snapshot(service)
            target_config_revision = (
                current.config_revision or self._catalog.service(service).initial.config_revision
            )
        return await self.deploy(
            service,
            target_version,
            target_config_revision,
            actor=actor,
            source="rollback",
            dry_run=dry_run,
        )

    async def restart(
        self, service: str, replica: int | None, *, actor: str, dry_run: bool = False
    ) -> ActionResult:
        self._catalog.service(service)
        async with self._locks[service]:
            before = await self.snapshot(service)
            targets = [c for c in before.containers if replica is None or c.replica == replica]
            if replica is not None and not targets:
                raise UnknownTargetError(f"replica {replica} of {service} does not exist")
            if not targets:
                raise PreconditionError(f"{service} has no replicas to restart")
            plan = [f"restart {c.name}" for c in targets]
            if dry_run:
                return ActionResult("restart", service, True, False, plan, before.to_dict())
            for c in targets:  # sequential = rolling restart
                await asyncio.to_thread(self._runtime.restart, c.id)
            log.info(
                "restarted",
                extra={"service": service, "replicas": [c.name for c in targets], "actor": actor},
            )
            after = await self.snapshot(service)
            return ActionResult(
                "restart", service, False, True, plan, before.to_dict(), after.to_dict()
            )

    async def scale(
        self, service: str, replicas: int, *, actor: str, dry_run: bool = False
    ) -> ActionResult:
        svc = self._catalog.service(service)
        if not svc.min_replicas <= replicas <= svc.max_replicas:
            raise BoundsError(
                f"replicas must be within [{svc.min_replicas}, {svc.max_replicas}], got {replicas}"
            )
        async with self._locks[service]:
            before = await self.snapshot(service)
            current = len(before.containers)
            version = before.version or svc.initial.version
            revision = before.config_revision or svc.initial.config_revision
            if replicas > current:
                plan = [
                    f"create {service}-{i} at {version}/{revision}"
                    for i in range(current + 1, replicas + 1)
                ]
            elif replicas < current:
                plan = [f"remove {c.name}" for c in before.containers if c.replica > replicas]
            else:
                plan = []
            if not plan:
                self._desired[service] = replicas
                return ActionResult(
                    "scale", service, dry_run, False, ["already at target; no-op"], before.to_dict()
                )
            if dry_run:
                return ActionResult("scale", service, True, False, plan, before.to_dict())
            if replicas > current:
                await self._require_image(svc.image_for(version))
                for i in range(current + 1, replicas + 1):
                    spec = self._spec(service, svc, i, version, revision, actor)
                    await asyncio.to_thread(self._runtime.create_and_start, spec)
            else:
                for c in sorted(before.containers, key=lambda c: -c.replica):
                    if c.replica > replicas:
                        await asyncio.to_thread(self._runtime.remove, c.id)
            self._desired[service] = replicas
            after = await self.snapshot(service)
            return ActionResult(
                "scale", service, False, True, plan, before.to_dict(), after.to_dict()
            )

    async def reconcile_initial(self) -> list[ActionResult]:
        """On startup: adopt existing replicas, or create the initial deployment if none exist."""
        results: list[ActionResult] = []
        for name, svc in self._catalog.services.items():
            existing = await self._list(name)
            if existing:
                self._desired[name] = max(len(existing), svc.min_replicas)
                head = existing[0]
                self.history.append(
                    DeploymentEvent(
                        service=name,
                        version=head.version,
                        config_revision=head.config_revision,
                        previous_version=None,
                        previous_config_revision=None,
                        deployed_at=head.labels.get(DEPLOYED_AT_LABEL, self._clock()),
                        deployed_by=head.labels.get(DEPLOYED_BY_LABEL, "unknown"),
                        source="reconcile",
                    )
                )
                continue
            results.append(
                await self.deploy(
                    name,
                    svc.initial.version,
                    svc.initial.config_revision,
                    actor="actuator:bootstrap",
                )
            )
        return results

    async def _record(self, event: DeploymentEvent) -> None:
        self.history.append(event)
        if self._event_sink is not None:
            try:
                await self._event_sink(event)
            except Exception:  # delivery is best-effort; history is kept locally regardless
                log.warning("deployment event delivery failed", exc_info=True)
