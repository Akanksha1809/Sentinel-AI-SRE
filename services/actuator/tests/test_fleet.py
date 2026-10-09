from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from actuator.catalog import ReleaseCatalog, UnknownTargetError
from actuator.fleet import BoundsError, DeploymentEvent, FleetManager, PreconditionError
from actuator.runtime import NotManagedError
from actuator.testing import FakeRuntime

CATALOG_PATH = Path(__file__).resolve().parents[3] / "deploy" / "actuator" / "releases.yaml"


class TestCatalog:
    def test_repo_catalogue_is_valid(self, catalog: ReleaseCatalog) -> None:
        svc = catalog.service("shop-api")
        assert svc.image_for("1.1.0") == "sentinel/shop-api:1.1.0"
        assert svc.config_revisions["r2"] == {"POOL_SIZE": "0"}

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda d: d["services"]["shop-api"]["config_revisions"]["r1"].update(
                {"LD_PRELOAD": "x"}
            ),
            lambda d: d["services"]["shop-api"]["releases"].update({"latest": {"image_tag": "x"}}),
            lambda d: d["services"]["shop-api"].update({"max_replicas": 50}),
            lambda d: d["services"]["shop-api"]["initial"].update({"version": "9.9.9"}),
            lambda d: d["services"]["shop-api"].update({"privileged": True}),
            lambda d: d["services"]["shop-api"]["releases"]["1.0.0"].update({"image_tag": "a b"}),
        ],
    )
    def test_unsafe_catalogues_rejected(self, tmp_path: Path, mutate: object) -> None:
        data = yaml.safe_load(CATALOG_PATH.read_text())
        mutate(data)  # type: ignore[operator]
        bad = tmp_path / "bad.yaml"
        bad.write_text(yaml.safe_dump(data))
        with pytest.raises(ValidationError):
            ReleaseCatalog.load(bad)


class TestDeployAndRollback:
    async def test_bootstrap_creates_initial_fleet(
        self, fleet: FleetManager, runtime: FakeRuntime
    ) -> None:
        await fleet.reconcile_initial()
        snap = await fleet.snapshot("shop-api")
        assert [(c.name, c.version, c.config_revision) for c in snap.containers] == [
            ("shop-api-1", "1.0.0", "r1"),
            ("shop-api-2", "1.0.0", "r1"),
        ]

    async def test_container_spec_is_hardened_and_catalogue_derived(
        self, fleet: FleetManager, runtime: FakeRuntime
    ) -> None:
        await fleet.reconcile_initial()
        spec = next(iter(runtime.specs.values()))
        assert spec.image == "sentinel/shop-api:1.0.0"
        assert (spec.memory_mb, spec.cpus, spec.pids) == (256, 0.5, 128)
        assert (spec.network, spec.aliases) == ("sentinel-app", ("shop-api",))
        assert spec.labels["sentinel.managed"] == "true"
        assert set(spec.env) == {
            "SERVICE_NAME",
            "APP_VERSION",
            "CONFIG_REVISION",
            "REPLICA",
            "POOL_SIZE",
            "CHAOS_TOKEN",
        }

    async def test_deploy_replaces_all_replicas_and_emits_event(
        self, fleet: FleetManager, runtime: FakeRuntime, events: list[DeploymentEvent]
    ) -> None:
        await fleet.reconcile_initial()
        result = await fleet.deploy("shop-api", "1.1.0", "r1", actor="faults:demo")
        assert result.changed
        assert {c.version for c in (await fleet.snapshot("shop-api")).containers} == {"1.1.0"}
        last = events[-1]
        assert (last.version, last.previous_version, last.source) == ("1.1.0", "1.0.0", "deploy")

    async def test_rollback_is_idempotent(self, fleet: FleetManager, runtime: FakeRuntime) -> None:
        await fleet.reconcile_initial()
        await fleet.deploy("shop-api", "1.1.0", "r1", actor="t")
        first = await fleet.rollback("shop-api", "1.0.0", None, actor="t")
        mutations = len(runtime.mutations)
        second = await fleet.rollback("shop-api", "1.0.0", None, actor="t")
        assert first.changed
        assert not second.changed
        assert second.plan == ["already at target; no-op"]
        assert len(runtime.mutations) == mutations

    async def test_rollback_keeps_config_revision_unless_specified(
        self, fleet: FleetManager
    ) -> None:
        await fleet.reconcile_initial()
        await fleet.deploy("shop-api", "1.0.0", "r2", actor="t")
        await fleet.rollback("shop-api", "1.0.0", "r1", actor="t")
        assert (await fleet.snapshot("shop-api")).config_revision == "r1"

    @pytest.mark.parametrize(
        ("version", "revision"), [("0.0.1", "r1"), ("1.0.0", "r9"), ("../../etc", "r1")]
    )
    async def test_unknown_targets_rejected_without_side_effects(
        self, fleet: FleetManager, runtime: FakeRuntime, version: str, revision: str
    ) -> None:
        await fleet.reconcile_initial()
        before = list(runtime.mutations)
        with pytest.raises(UnknownTargetError):
            await fleet.deploy("shop-api", version, revision, actor="t")
        assert runtime.mutations == before

    async def test_unknown_service_rejected(self, fleet: FleetManager) -> None:
        with pytest.raises(UnknownTargetError):
            await fleet.restart("postgres", None, actor="t")

    async def test_missing_image_is_precondition_error(self, catalog: ReleaseCatalog) -> None:
        fleet = FleetManager(catalog, FakeRuntime(images=set()), "net", None)
        with pytest.raises(PreconditionError):
            await fleet.reconcile_initial()


class TestDryRun:
    async def test_dry_run_plans_without_mutating(
        self, fleet: FleetManager, runtime: FakeRuntime
    ) -> None:
        await fleet.reconcile_initial()
        before = list(runtime.mutations)
        deploy = await fleet.deploy("shop-api", "1.1.0", "r1", actor="t", dry_run=True)
        restart = await fleet.restart("shop-api", None, actor="t", dry_run=True)
        scale = await fleet.scale("shop-api", 3, actor="t", dry_run=True)
        assert runtime.mutations == before
        assert (deploy.dry_run, deploy.changed, len(deploy.plan)) == (True, False, 2)
        assert restart.plan == ["restart shop-api-1", "restart shop-api-2"]
        assert scale.plan == ["create shop-api-3 at 1.0.0/r1"]


class TestRestartAndScale:
    async def test_restart_single_replica(self, fleet: FleetManager, runtime: FakeRuntime) -> None:
        await fleet.reconcile_initial()
        await fleet.restart("shop-api", 2, actor="t")
        assert runtime.mutations[-1] == ("restart", "shop-api-2")

    async def test_restart_missing_replica(self, fleet: FleetManager) -> None:
        await fleet.reconcile_initial()
        with pytest.raises(UnknownTargetError):
            await fleet.restart("shop-api", 3, actor="t")

    @pytest.mark.parametrize("replicas", [0, 4, -1, 100])
    async def test_scale_bounds(self, fleet: FleetManager, replicas: int) -> None:
        await fleet.reconcile_initial()
        with pytest.raises(BoundsError):
            await fleet.scale("shop-api", replicas, actor="t")

    async def test_scale_up_then_down(self, fleet: FleetManager) -> None:
        await fleet.reconcile_initial()
        await fleet.scale("shop-api", 3, actor="t")
        assert len((await fleet.snapshot("shop-api")).containers) == 3
        down = await fleet.scale("shop-api", 1, actor="t")
        assert down.plan == ["remove shop-api-2", "remove shop-api-3"]
        snap = await fleet.snapshot("shop-api")
        assert [c.name for c in snap.containers] == ["shop-api-1"]
        assert snap.desired_replicas == 1
        # a later deploy only replaces the desired replica count
        result = await fleet.deploy("shop-api", "1.1.0", "r1", actor="t")
        assert len(result.plan) == 1


class TestManagedBoundary:
    async def test_foreign_containers_are_invisible(
        self, fleet: FleetManager, runtime: FakeRuntime
    ) -> None:
        runtime.add_foreign("jenkins")
        await fleet.reconcile_initial()
        snap = await fleet.snapshot("shop-api")
        assert "jenkins" not in [c.name for c in snap.containers]

    def test_runtime_refuses_foreign_container_ids(self, runtime: FakeRuntime) -> None:
        cid = runtime.add_foreign("jenkins")
        with pytest.raises(NotManagedError):
            runtime.restart(cid)
        with pytest.raises(NotManagedError):
            runtime.remove(cid)


class TestAdoption:
    async def test_existing_fleet_is_adopted_not_recreated(
        self, catalog: ReleaseCatalog, runtime: FakeRuntime
    ) -> None:
        first = FleetManager(catalog, runtime, "net", None)
        await first.reconcile_initial()
        await first.scale("shop-api", 3, actor="t")
        mutations = len(runtime.mutations)
        restarted = FleetManager(catalog, runtime, "net", None)  # simulate actuator restart
        await restarted.reconcile_initial()
        assert len(runtime.mutations) == mutations
        assert restarted.desired_replicas("shop-api") == 3
        assert restarted.history[-1].source == "reconcile"


def test_load_secret_files(tmp_path: Path) -> None:
    from actuator.config import load_secret_files

    (tmp_path / "actuator_token").write_text("abc\n")
    (tmp_path / "fault_token").write_text("   ")
    (tmp_path / "unrelated").write_text("x")
    found = load_secret_files(tmp_path)
    assert set(found) == {"actuator_token"}
    assert found["actuator_token"].get_secret_value() == "abc"
