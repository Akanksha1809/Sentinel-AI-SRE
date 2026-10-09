"""Security invariants of the Compose deployment (threat model T8, T9, T13, T16)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
COMPOSE = REPO / "deploy" / "compose" / "docker-compose.yml"

SOCKET_PROXIES = {"socket-proxy-rw", "socket-proxy-ro"}
# Services that may not use a read-only root filesystem, with the reason.
WRITABLE_ROOTFS = {"postgres": "entrypoint initialises PGDATA and /var/run/postgresql"}
# Services without a container healthcheck, with the reason.
NO_HEALTHCHECK = {"loki": "distroless image has no shell/wget; readiness checked from host"}
# Services that need specific capabilities back.
CAP_ADD_ALLOWED = {"postgres": {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}}


def _compose() -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(COMPOSE.read_text())
    return data


def _runtime_services() -> dict[str, dict[str, Any]]:
    """Services Compose actually runs (excludes build-only `images` profile entries)."""
    return {
        n: s for n, s in _compose()["services"].items() if "images" not in s.get("profiles", [])
    }


def _merged(svc: dict[str, Any]) -> dict[str, Any]:
    # yaml.safe_load already resolves `<<: *hardening` merges.
    return svc


@pytest.fixture(scope="module")
def services() -> dict[str, dict[str, Any]]:
    return {n: _merged(s) for n, s in _runtime_services().items()}


def test_only_socket_proxies_mount_the_docker_socket(services: dict[str, dict[str, Any]]) -> None:
    offenders = [
        n
        for n, s in services.items()
        if n not in SOCKET_PROXIES and any("docker.sock" in str(v) for v in s.get("volumes", []))
    ]
    assert offenders == []


def test_socket_proxies_are_network_isolated(services: dict[str, dict[str, Any]]) -> None:
    networks = _compose()["networks"]
    for name in SOCKET_PROXIES:
        svc_nets = services[name]["networks"]
        assert len(svc_nets) == 1, name
        assert networks[svc_nets[0]].get("internal") is True, name
        assert services[name]["read_only"] is True
        assert "ports" not in services[name]


def test_rw_proxy_blocks_exec_and_host_mounts(services: dict[str, dict[str, Any]]) -> None:
    cmd = " ".join(services["socket-proxy-rw"]["command"])
    assert "-allowbindmountfrom=/nonexistent" in cmd
    assert "exec" not in cmd
    assert "-allowfrom=docker-guard" in cmd
    ro_cmd = " ".join(services["socket-proxy-ro"]["command"])
    assert "-allowPOST" not in ro_cmd
    assert "-allowDELETE" not in ro_cmd


def test_every_service_is_hardened(services: dict[str, dict[str, Any]]) -> None:
    for name, svc in services.items():
        assert svc.get("mem_limit"), f"{name}: no mem_limit"
        assert svc.get("cap_drop") == ["ALL"], f"{name}: must drop all capabilities"
        assert "no-new-privileges:true" in svc.get("security_opt", []), name
        assert not svc.get("privileged"), f"{name}: privileged"
        assert svc.get("network_mode") != "host", f"{name}: host network"
        assert svc.get("pid") != "host", f"{name}: host pid"
        assert set(svc.get("cap_add", [])) <= CAP_ADD_ALLOWED.get(name, set()), name
        if name not in WRITABLE_ROOTFS:
            assert svc.get("read_only") is True, f"{name}: rootfs should be read-only"


def test_healthchecks_present_or_justified(services: dict[str, dict[str, Any]]) -> None:
    dockerfile = (REPO / "deploy" / "docker" / "python-service.Dockerfile").read_text()
    assert "HEALTHCHECK" in dockerfile  # images built from this repo carry their own
    missing = {
        n
        for n, s in services.items()
        if "healthcheck" not in s and not s["image"].startswith("sentinel/")
    }
    assert missing == set(NO_HEALTHCHECK)


def test_ports_bind_to_loopback_only(services: dict[str, dict[str, Any]]) -> None:
    for name, svc in services.items():
        for port in svc.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), f"{name}: {port} is exposed beyond loopback"


def test_images_are_pinned(services: dict[str, dict[str, Any]]) -> None:
    for name, svc in services.items():
        image = svc["image"]
        if image.startswith("sentinel/"):
            continue  # built locally from this repo
        tag = image.rsplit(":", 1)[-1] if ":" in image else ""
        # exact release: x.y.z, or x.y for projects (like postgres) without a patch level
        assert re.fullmatch(r"v?\d+\.\d+(\.\d+)?", tag), f"{name}: image {image} not pinned"


def test_bind_mounts_are_read_only_repo_config(services: dict[str, dict[str, Any]]) -> None:
    for name, svc in services.items():
        for vol in svc.get("volumes", []):
            src = str(vol).split(":")[0]
            if src.startswith(("/", ".")) and "docker.sock" not in src:
                assert str(vol).endswith(":ro"), f"{name}: writable bind mount {vol}"
                assert src.startswith("../"), f"{name}: bind mount outside repo: {vol}"


def test_no_inline_secrets(services: dict[str, dict[str, Any]]) -> None:
    pattern = re.compile(r"(PASSWORD|TOKEN|SECRET|KEY)(?!_FILE|__FILE)", re.IGNORECASE)
    for name, svc in services.items():
        for key, value in (svc.get("environment") or {}).items():
            if pattern.search(key):
                assert str(value).startswith("/run/secrets/"), f"{name}: inline secret {key}"
    for secret in _compose()["secrets"].values():
        assert secret["file"].startswith("../../secrets/")


def test_actuator_reaches_docker_only_through_guard(services: dict[str, dict[str, Any]]) -> None:
    actuator, guard = services["actuator"], services["docker-guard"]
    assert actuator["environment"]["ACTUATOR_DOCKER_HOST"] == "tcp://docker-guard:2375"
    rw_nets = set(services["socket-proxy-rw"]["networks"])
    assert not rw_nets & set(actuator["networks"]), "actuator must not reach the rw proxy"
    assert rw_nets <= set(guard["networks"])
    assert "volumes" not in guard
