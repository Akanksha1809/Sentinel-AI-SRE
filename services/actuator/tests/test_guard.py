from __future__ import annotations

import copy
import json
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from actuator.guard import GuardSettings, GuardViolationError, create_guard_app, validate_create
from actuator.runtime import ContainerSpec, DockerRuntime

SETTINGS = GuardSettings()
NAME = "shop-api-1"


def actuator_body() -> dict[str, Any]:
    """The exact create body the actuator sends (built by the real DockerRuntime)."""
    runtime = DockerRuntime("tcp://127.0.0.1:1", timeout_s=1, api_version="1.54")
    spec = ContainerSpec(
        name=NAME,
        image="sentinel/shop-api:1.0.0",
        env={
            "SERVICE_NAME": "shop-api",
            "APP_VERSION": "1.0.0",
            "CONFIG_REVISION": "r1",
            "REPLICA": "1",
            "POOL_SIZE": "10",
            "CHAOS_TOKEN": "x",
        },
        labels={"sentinel.managed": "true", "sentinel.service": "shop-api"},
        network="sentinel-app",
        aliases=("shop-api",),
        memory_mb=256,
        cpus=0.5,
        pids=128,
    )
    return runtime.build_create_config(spec)


def test_actuator_generated_body_is_admitted() -> None:
    validate_create(actuator_body(), SETTINGS, NAME)


def _set(path: str, value: Any) -> Callable[[dict[str, Any]], None]:
    def mutate(body: dict[str, Any]) -> None:
        target = body
        *parents, leaf = path.split(".")
        for p in parents:
            target = target.setdefault(p, {})
        target[leaf] = value

    return mutate


ATTACKS: dict[str, Callable[[dict[str, Any]], None]] = {
    "privileged": _set("HostConfig.Privileged", True),
    "host bind": _set("HostConfig.Binds", ["/:/host"]),
    "mounts": _set("HostConfig.Mounts", [{"Type": "bind", "Source": "/", "Target": "/h"}]),
    "devices": _set("HostConfig.Devices", [{"PathOnHost": "/dev/kmsg"}]),
    "cap add": _set("HostConfig.CapAdd", ["SYS_ADMIN"]),
    "keep caps": _set("HostConfig.CapDrop", []),
    "host pid": _set("HostConfig.PidMode", "host"),
    "host ipc": _set("HostConfig.IpcMode", "host"),
    "userns host": _set("HostConfig.UsernsMode", "host"),
    "host network": _set("HostConfig.NetworkMode", "host"),
    "join container ns": _set("HostConfig.NetworkMode", "container:jenkins"),
    "publish port": _set("HostConfig.PortBindings", {"8000/tcp": [{"HostPort": "80"}]}),
    "seccomp off": _set("HostConfig.SecurityOpt", ["no-new-privileges:true", "seccomp=unconfined"]),
    "drop nnp": _set("HostConfig.SecurityOpt", []),
    "writable rootfs": _set("HostConfig.ReadonlyRootfs", False),
    "no memory limit": _set("HostConfig.Memory", 0),
    "huge memory": _set("HostConfig.Memory", 64 * 2**30),
    "swap": _set("HostConfig.MemorySwap", -1),
    "no cpu limit": _set("HostConfig.NanoCpus", 0),
    "no pids limit": _set("HostConfig.PidsLimit", 0),
    "sysctls": _set("HostConfig.Sysctls", {"kernel.panic": "1"}),
    "runtime": _set("HostConfig.Runtime", "sysbox"),
    "volumes from": _set("HostConfig.VolumesFrom", ["jenkins"]),
    "exec tmpfs": _set("HostConfig.Tmpfs", {"/tmp": "rw"}),
    "other image": _set("Image", "alpine:3.20"),
    "image digest trick": _set("Image", "sentinel/shop-api:1.0.0@sha256:abc"),
    "unmanaged": _set("Labels", {"sentinel.service": "shop-api"}),
    "custom cmd": _set("Cmd", ["sh", "-c", "cat /etc/shadow"]),
    "custom entrypoint": _set("Entrypoint", ["/bin/sh"]),
    "run as root": _set("User", "0"),
    "volumes": _set("Volumes", {"/data": {}}),
    "ld preload": _set("Env", ["LD_PRELOAD=/tmp/x.so"]),
    "foreign network": _set("NetworkingConfig.EndpointsConfig", {"bridge": {}}),
}


@pytest.mark.parametrize("attack", sorted(ATTACKS))
def test_dangerous_specs_are_refused(attack: str) -> None:
    body = copy.deepcopy(actuator_body())
    ATTACKS[attack](body)
    with pytest.raises(GuardViolationError):
        validate_create(body, SETTINGS, NAME)


@pytest.mark.parametrize("name", [None, "jenkins", "ai-platform-engineer-control-plane", "x;y"])
def test_container_name_must_follow_managed_scheme(name: str | None) -> None:
    with pytest.raises(GuardViolationError):
        validate_create(actuator_body(), SETTINGS, name)


class Upstream:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.containers = {
            "managed1": {"Config": {"Labels": {"sentinel.managed": "true"}}},
            "jenkins": {"Config": {"Labels": {"com.docker.compose.project": "other"}}},
        }

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, request.url.path))
        parts = request.url.path.split("/")
        if request.method == "GET" and parts[-1] == "json" and parts[-2] != "containers":
            cid = parts[-2]
            if cid in self.containers:
                return httpx.Response(200, json=self.containers[cid])
            return httpx.Response(404, json={"message": "no such container"})
        return httpx.Response(204 if request.method != "GET" else 200, json={})


@pytest.fixture
def upstream() -> Upstream:
    return Upstream()


@pytest.fixture
def client(upstream: Upstream) -> Iterator[TestClient]:
    app = create_guard_app(SETTINGS, transport=httpx.MockTransport(upstream.handler))
    with TestClient(app) as c:
        yield c


def test_valid_create_is_forwarded(client: TestClient, upstream: Upstream) -> None:
    r = client.post(
        "/v1.54/containers/create?name=shop-api-1",
        content=json.dumps(actuator_body()),
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 204
    assert upstream.calls == [("POST", "/v1.54/containers/create")]


def test_privileged_create_never_reaches_upstream(client: TestClient, upstream: Upstream) -> None:
    body = actuator_body()
    body["HostConfig"]["Privileged"] = True
    r = client.post("/v1.54/containers/create?name=shop-api-1", content=json.dumps(body))
    assert r.status_code == 403
    assert "Privileged" in r.json()["message"]
    assert upstream.calls == []


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/v1.54/containers/jenkins/stop"),
        ("POST", "/v1.54/containers/jenkins/restart"),
        ("POST", "/v1.54/containers/jenkins/kill"),
        ("DELETE", "/v1.54/containers/jenkins"),
        ("POST", "/v1.54/containers/doesnotexist/restart"),
    ],
)
def test_mutations_on_unmanaged_containers_refused(
    client: TestClient, upstream: Upstream, method: str, path: str
) -> None:
    r = client.request(method, path)
    assert r.status_code == 403
    assert all(m == "GET" for m, _ in upstream.calls)  # only the label lookup went upstream


def test_mutation_on_managed_container_forwarded(client: TestClient, upstream: Upstream) -> None:
    assert client.post("/v1.54/containers/managed1/restart?t=10").status_code == 204
    assert upstream.calls[-1] == ("POST", "/v1.54/containers/managed1/restart")


@pytest.mark.parametrize(
    "path",
    [
        "/v1.54/containers/managed1/exec",
        "/v1.54/images/create",
        "/v1.54/networks/create",
        "/v1.54/volumes/create",
    ],
)
def test_other_writes_refused(client: TestClient, upstream: Upstream, path: str) -> None:
    assert client.post(path).status_code == 403
    assert upstream.calls == []


def test_reads_pass_through(client: TestClient, upstream: Upstream) -> None:
    assert client.get("/v1.54/containers/json").status_code == 200
    assert upstream.calls == [("GET", "/v1.54/containers/json")]


def test_oversized_body_refused(client: TestClient) -> None:
    r = client.post("/v1.54/containers/create?name=shop-api-1", content=b"x" * 70_000)
    assert r.status_code == 403


def test_newline_suffixed_paths_are_denied(client: TestClient, upstream: Upstream) -> None:
    for path in ("/v1.54/containers/create%0A", "/v1.54/containers/jenkins%0A/stop"):
        # Refused by the guard (403) or unroutable (404): never forwarded either way.
        assert client.post(path, content=b"{}").status_code in (403, 404)
    assert upstream.calls == []
