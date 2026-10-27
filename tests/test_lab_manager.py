import json
import sys
import time
from pathlib import Path

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab-manager"))
pytest.importorskip("docker")

from docker.errors import NotFound

from lab_manager import main as manager


def test_dind_uses_runc_for_image_builds_and_registers_runsc_for_labs():
    daemon_config = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "docker"
            / "dind"
            / "daemon.json"
        ).read_text()
    )

    assert daemon_config["default-runtime"] == "runc"
    assert daemon_config["runtimes"]["runsc"]["path"] == "/usr/local/bin/runsc"


def test_lab_image_build_fingerprint_includes_build_revision(monkeypatch, tmp_path):
    monkeypatch.setattr(manager, "LAB_IMAGE_CONTEXT", tmp_path)
    first = manager.fingerprint_lab_image_context()
    monkeypatch.setattr(manager, "LAB_IMAGE_BUILD_REVISION", "test-revision")

    assert manager.fingerprint_lab_image_context() != first


def test_binary_challenges_are_explicitly_allowlisted_for_launch_and_materials():
    assert manager.CHALLENGE_IMAGES["reverse-01"] == "reverse-01"
    assert manager.CHALLENGE_IMAGES["pwn-01"] == "pwn-01"
    assert manager.ALLOWED_MATERIAL_KEYS.issuperset({"reverse-01", "pwn-01"})
    update = manager.MaterialUpdate.model_validate(
        {"materials": {"reverse-01": "CTF{rev}", "pwn-01": "CTF{vm}"}}
    )
    assert set(update.materials) == {"reverse-01", "pwn-01"}


def test_unchanged_material_sync_does_not_wait_for_lab_launch_lock(monkeypatch):
    materials = {
        challenge: f"CTF{{{challenge}}}"
        for challenge in manager.ALLOWED_MATERIAL_KEYS
    }
    monkeypatch.setattr(manager.app.state, "materials", materials, raising=False)
    monkeypatch.setattr(
        manager.app.state,
        "materials_secret",
        "manager-test-secret-that-is-at-least-32-characters",
        raising=False,
    )

    class UnexpectedLock:
        def __enter__(self):
            raise AssertionError("An unchanged material sync must not wait for lab launches")

        def __exit__(self, *_):
            return False

    monkeypatch.setattr(manager, "LAB_LAUNCH_LOCK", UnexpectedLock())
    request = manager.Request(
        {
            "type": "http",
            "method": "PUT",
            "path": "/internal/materials",
            "headers": [],
            "app": manager.app,
        }
    )

    response = manager.update_materials(
        manager.MaterialUpdate.model_validate({"materials": materials}),
        request,
        secret="manager-test-secret-that-is-at-least-32-characters",
    )

    assert response == {"status": "updated"}


def test_missing_lab_image_is_built_without_using_stale_layers(monkeypatch, tmp_path):
    class MissingImage(Exception):
        pass

    class FakeImage:
        def tag(self, *args, **kwargs):
            return True

    class FakeImages:
        def __init__(self):
            self.items = {}
            self.build_options = None

        def get(self, reference):
            if reference not in self.items:
                raise MissingImage(reference)
            return self.items[reference]

        def build(self, **options):
            self.build_options = options
            self.items[options["tag"]] = FakeImage()

    class FakeClient:
        def __init__(self):
            self.images = FakeImages()

    monkeypatch.setattr(manager, "ImageNotFound", MissingImage)
    monkeypatch.setattr(manager, "LAB_IMAGE_CONTEXT", tmp_path)
    monkeypatch.setattr(manager, "CHALLENGE_IMAGES", {})
    client = FakeClient()

    assert manager.ensure_lab_images(client) == {}
    assert client.images.build_options["nocache"] is True


class FakeNetwork:
    def __init__(self, name: str, labels: dict[str, str]):
        self.name = name
        self.labels = labels
        self.removed = False

    def remove(self):
        self.removed = True


class FakeNetworks:
    def __init__(self):
        self.items: list[FakeNetwork] = []
        self.last_create: dict = {}

    def create(self, name: str, **kwargs):
        self.last_create = {"name": name, **kwargs}
        network = FakeNetwork(name, kwargs["labels"])
        self.items.append(network)
        return network

    def get(self, name: str):
        for network in self.items:
            if network.name == name and not network.removed:
                return network
        raise NotFound("network not found")

    def list(self, filters: dict | None = None):
        return [network for network in self.items if not network.removed]


class FakeContainer:
    def __init__(self, collection, options: dict):
        self.collection = collection
        self.name = options["name"]
        self.labels = options["labels"]
        self.status = "running"
        self.attrs = {
            "NetworkSettings": {
                "Ports": {
                    "8000/tcp": [{"HostIp": manager.DOCKER_GATEWAY, "HostPort": "49152"}]
                }
            }
        }

    def reload(self):
        return None

    def start(self):
        if self.collection.start_error is not None:
            raise self.collection.start_error
        self.status = "running"

    def remove(self, force: bool = False):
        self.status = "removed"
        self.collection.items.remove(self)


class FakeContainers:
    def __init__(self):
        self.items: list[FakeContainer] = []
        self.last_create: dict = {}
        self.start_error: Exception | None = None

    def list(self, all: bool = False, filters: dict | None = None):
        filters = filters or {}
        result = [
            item for item in self.items if all or item.status == "running"
        ]
        labels = filters.get("label", [])
        if isinstance(labels, str):
            labels = [labels]
        for expression in labels:
            key, value = expression.split("=", 1)
            result = [item for item in result if item.labels.get(key) == value]
        return result

    def get(self, name: str):
        for item in self.items:
            if item.name == name:
                return item
        raise NotFound("container not found")

    def create(self, **options):
        self.last_create = options
        container = FakeContainer(self, options)
        self.items.append(container)
        container.status = "created"
        return container


class FakeDockerClient:
    def __init__(self):
        self.containers = FakeContainers()
        self.networks = FakeNetworks()


def test_create_lab_uses_only_the_fixed_hardened_container_policy(monkeypatch):
    monkeypatch.setattr(manager, "lab_is_ready", lambda target: True)
    client = FakeDockerClient()
    token, reused = manager.create_lab(
        client,
        "cyberarena/web-01:approved",
        42,
        "web-01",
        "CTF{only_this_challenge}",
    )

    options = client.containers.last_create
    assert not reused
    assert manager.TOKEN_PATTERN.fullmatch(token)
    assert options["runtime"] == "runsc"
    assert options["network"] == client.networks.last_create["name"]
    assert client.networks.last_create["internal"] is False
    assert client.networks.last_create["options"] == {
        "com.docker.network.bridge.enable_ip_masquerade": "false",
        "com.docker.network.bridge.enable_icc": "false",
    }
    assert options["mem_limit"] == options["memswap_limit"] == "128m"
    assert options["nano_cpus"] == 250_000_000
    assert options["pids_limit"] == 64
    assert [
        (ulimit.name, ulimit.soft, ulimit.hard) for ulimit in options["ulimits"]
    ] == [("nproc", 10, 10)]
    assert options["read_only"] is True
    assert options["cap_drop"] == ["ALL"]
    assert options["security_opt"] == ["no-new-privileges=true"]
    assert options["tmpfs"] == {"/tmp": "rw,noexec,nosuid,size=16m"}
    assert options["restart_policy"] == {"Name": "no"}
    assert options["environment"] == {
        "LAB_CHALLENGE_KEY": "web-01",
        "LAB_CHALLENGE_FLAG": "CTF{only_this_challenge}",
    }
    assert "privileged" not in options

    assert manager.lab_target(client, token) == "http://172.31.250.3:49152"


def test_create_lab_cleans_up_container_and_network_when_runsc_fails_to_start():
    client = FakeDockerClient()
    client.containers.start_error = RuntimeError("runsc sandbox failed to start")

    with pytest.raises(RuntimeError, match="runsc sandbox failed to start"):
        manager.create_lab(
            client,
            "cyberarena/web-01:approved",
            42,
            "web-01",
            "CTF{only_this_challenge}",
        )

    assert client.containers.items == []
    assert client.networks.items[0].removed is True


def test_create_lab_rejects_launch_when_global_capacity_is_full():
    client = FakeDockerClient()
    for index in range(manager.MAX_GLOBAL_LABS):
        client.containers.items.append(
            FakeContainer(
                client.containers,
                {
                    "name": f"existing-{index}",
                    "labels": {
                        manager.MANAGED_LABEL: "true",
                        manager.OWNER_LABEL: str(index + 1),
                        manager.EXPIRES_LABEL: str(time.time() + 60),
                        manager.TOKEN_LABEL: f"token-{index}",
                    },
                },
            )
        )

    with pytest.raises(HTTPException) as raised:
        manager.create_lab(
            client,
            "cyberarena/web-01:approved",
            100,
            "web-01",
            "CTF{flag}",
        )

    assert raised.value.status_code == 429
    assert client.containers.last_create == {}


def test_orphaned_lab_networks_are_removed():
    client = FakeDockerClient()
    orphan = FakeNetwork(
        "ctf_lab_net_orphan",
        {manager.MANAGED_LABEL: "true"},
    )
    client.networks.items.append(orphan)

    manager.remove_orphaned_networks(client)

    assert orphan.removed is True


def test_launch_api_authenticates_and_rejects_unknown_or_custom_requests():
    manager.app.state.launch_secret = "manager-test-secret-that-is-at-least-32-characters"
    manager.app.state.materials = {}
    request = manager.Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/internal/labs",
            "headers": [],
            "app": manager.app,
        }
    )

    with pytest.raises(HTTPException) as unauthorized:
        manager.start_lab(
            manager.LabLaunch(user_id=1, challenge_id="web-01"),
            request,
            secret=None,
        )
    assert unauthorized.value.status_code == 401

    with pytest.raises(HTTPException) as unknown_challenge:
        manager.start_lab(
            manager.LabLaunch(user_id=1, challenge_id="arbitrary-image"),
            request,
            secret=manager.app.state.launch_secret,
        )
    assert unknown_challenge.value.status_code == 400

    with pytest.raises(ValidationError) as unsupported_fields:
        manager.LabLaunch.model_validate(
            {"user_id": 1, "challenge_id": "web-01", "image": "attacker-image"}
        )
    assert unsupported_fields.value.errors()[0]["type"] == "extra_forbidden"
