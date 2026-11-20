import hashlib
import io
import sys
import tarfile
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab-manager"))
pytest.importorskip("docker")

from lab_manager import main as manager
from tests.conftest import (
    admin_client,
    csrf,
    lab_manager_test_app,
    register,
)


def custom_archive(dockerfile: str) -> bytes:
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode="w:gz") as archive:
        for name, value in (
            ("Dockerfile", dockerfile),
            ("main.py", "app = None\n"),
        ):
            payload = value.encode()
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    return content.getvalue()


def test_admin_custom_lab_build_is_verified_before_publish_and_launch(monkeypatch, client):
    from app.platform.routers import challenges as challenge_routes
    from app.platform.routers import html as html_routes

    admin_client(client)
    page = client.get("/admin/challenges/lab/new")
    assert page.status_code == 200
    assert "Собрать, проверить и опубликовать" in page.text
    assert "через Nginx" in page.text

    created = []

    async def successful_build(challenge_id: int, flag: str, archive: bytes) -> str:
        created.append((challenge_id, flag, archive))
        return f"cyberarena/custom-{challenge_id}:{hashlib.sha256(archive).hexdigest()[:20]}"

    monkeypatch.setattr(html_routes, "build_custom_lab", successful_build)
    payload = custom_archive("FROM local-base\nCMD [\"python\", \"main.py\"]\n")
    response = client.post(
        "/admin/challenges/lab",
        data={
            "csrf_token": csrf(client),
            "title": "WEB-CUSTOM — Проверка",
            "category": "Web",
            "description": "Исследуйте изолированное учебное приложение.",
            "points": "275",
            "flag": "CTF{custom_lab_ready}",
        },
        files={"archive": ("custom.tar.gz", payload, "application/gzip")},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/admin/challenges"
    challenge_id, flag, uploaded_archive = created[0]
    assert flag == "CTF{custom_lab_ready}"
    assert uploaded_archive == payload

    admin_view = client.get(f"/api/admin/challenges/{challenge_id}").json()
    assert admin_view["lab_build_status"] == "ready"
    assert admin_view["has_isolated_lab"] is True
    assert admin_view["is_published"] is True
    assert lab_manager_test_app.state.materials[f"custom-{challenge_id}"] == flag

    from app.platform.services import task_materials

    updated_flag = "CTF{custom_lab_updated}"
    lab_manager_test_app.state.missing_custom_images.add(f"custom-{challenge_id}")
    rebuilt = []

    async def restore_missing_image(restored_id: int, restored_flag: str, archive: bytes) -> str:
        rebuilt.append((restored_id, restored_flag, archive))
        lab_manager_test_app.state.missing_custom_images.clear()
        return (
            f"cyberarena/custom-{restored_id}:"
            f"{hashlib.sha256(archive).hexdigest()[:20]}"
        )

    monkeypatch.setattr(task_materials, "build_custom_lab", restore_missing_image)
    changed = client.patch(
        f"/api/admin/challenges/{challenge_id}",
        json={"flag": updated_flag},
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert changed.status_code == 200
    assert rebuilt == [(challenge_id, updated_flag, uploaded_archive)]
    assert lab_manager_test_app.state.materials[f"custom-{challenge_id}"] == updated_flag
    expected_image = (
        f"cyberarena/custom-{challenge_id}:"
        f"{hashlib.sha256(uploaded_archive).hexdigest()[:20]}"
    )
    assert lab_manager_test_app.state.custom_images[f"custom-{challenge_id}"] == expected_image

    register(client, "customplayer")
    detail = client.get(f"/challenges/{challenge_id}")
    assert detail.status_code == 200
    assert "Открыть лабораторию" in detail.text

    launched = []

    async def fake_start_user_lab(user_id: int, challenge_key: str) -> str:
        launched.append((user_id, challenge_key))
        return "/lab-session/" + "d" * 40 + "/"

    monkeypatch.setattr(challenge_routes, "start_user_lab", fake_start_user_lab)
    result = client.post(
        f"/api/labs/{challenge_id}/start",
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert result.status_code == 200
    assert result.json()["access_path"] == "/lab-session/" + "d" * 40 + "/"
    assert launched == [(2, f"custom-{challenge_id}")]


def test_failed_custom_lab_remains_unpublished_and_cannot_be_published(monkeypatch, client):
    from app.platform.routers import html as html_routes

    admin_client(client)

    async def failed_build(*_args) -> str:
        raise HTTPException(status_code=503, detail="Проверка через Nginx не прошла.")

    monkeypatch.setattr(html_routes, "build_custom_lab", failed_build)
    response = client.post(
        "/admin/challenges/lab",
        data={
            "csrf_token": csrf(client),
            "title": "WEB-CUSTOM — Недоступное приложение",
            "category": "Web",
            "description": "Тест сбоя проверки.",
            "points": "150",
            "flag": "CTF{custom_lab_failed}",
        },
        files={"archive": ("custom.tar.gz", custom_archive("FROM local-base\nCMD true\n"), "application/gzip")},
    )
    assert response.status_code == 503
    assert "не опубликована" in response.text.lower()
    assert "Проверка через Nginx не прошла." in response.text

    challenge = client.get("/api/admin/challenges").json()
    failed = next(item for item in challenge if item["title"] == "WEB-CUSTOM — Недоступное приложение")
    assert failed["lab_build_status"] == "failed"
    assert failed["is_published"] is False
    assert client.post(
        f"/api/admin/challenges/{failed['id']}/publish",
        headers={"X-CSRF-Token": csrf(client)},
    ).status_code == 409
    assert all(item["id"] != failed["id"] for item in client.get("/api/challenges").json())


def test_custom_lab_build_prefers_cached_bases_and_bounds_build_resources(monkeypatch, tmp_path):
    base_image = "cyberarena/lab-base:custom"
    monkeypatch.setattr(manager, "LAB_IMAGE_CONTEXT", tmp_path)
    verified = []

    class FakeImage:
        attrs = {"Size": 1024}

    class FakeImages:
        def __init__(self):
            self.options = None
            self.image = FakeImage()

        def build(self, **options):
            self.options = options
            return self.image, []

        def get(self, _reference):
            return self.image

    class FakeClient:
        def __init__(self):
            self.images = FakeImages()

    fake_client = FakeClient()
    monkeypatch.setattr(
        manager,
        "verify_custom_image",
        lambda client, image_ref, challenge_key, flag: verified.append(
            (client, image_ref, challenge_key, flag)
        ),
    )
    archive = custom_archive(
        f"FROM {base_image}\nCOPY main.py /srv/custom/main.py\nCMD [\"python\", \"main.py\"]\n"
    )

    image_ref = manager.build_custom_image(fake_client, 42, "CTF{custom}", archive)

    assert image_ref == f"cyberarena/custom-42:{hashlib.sha256(archive).hexdigest()[:20]}"
    assert fake_client.images.options["network_mode"] == "bridge"
    assert fake_client.images.options["pull"] is False
    assert fake_client.images.options["timeout"] == manager.CUSTOM_BUILD_TIMEOUT_SECONDS
    assert fake_client.images.options["container_limits"] == {
        "memory": manager.CUSTOM_BUILD_MEMORY_LIMIT,
        "memswap": manager.CUSTOM_BUILD_MEMORY_LIMIT,
        "cpushares": 1024,
    }
    assert verified == [(fake_client, image_ref, "custom-42", "CTF{custom}")]


def test_custom_php_lab_can_use_an_external_base_image(monkeypatch, tmp_path):
    monkeypatch.setattr(manager, "LAB_IMAGE_CONTEXT", tmp_path)
    verified = []

    class FakeImage:
        attrs = {"Size": 1024}

    class FakeImages:
        def __init__(self):
            self.build_options = None

        def build(self, **options):
            self.build_options = options
            return FakeImage(), []

        def get(self, _reference):
            return FakeImage()

    class FakeClient:
        def __init__(self):
            self.images = FakeImages()

    client = FakeClient()
    monkeypatch.setattr(
        manager,
        "verify_custom_image",
        lambda *_args: verified.append(True),
    )
    archive = custom_archive(
        "FROM php:7.4.33-cli-alpine3.16 AS runtime\n"
        "WORKDIR /srv/custom\n"
        "COPY index.php .\n"
        'CMD ["php", "-S", "0.0.0.0:8000", "index.php"]\n'
    )

    image_ref = manager.build_custom_image(client, 47, "CTF{php}", archive)

    assert image_ref.startswith("cyberarena/custom-47:")
    assert client.images.build_options["network_mode"] == "bridge"
    assert client.images.build_options["pull"] is False
    assert verified == [True]


def test_custom_lab_dockerfile_allows_build_commands_and_multistage_images(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM golang:1.24 AS builder\n"
        "WORKDIR /src\n"
        "COPY . .\n"
        "RUN go build -o /service .\n"
        "FROM alpine:3.22\n"
        "COPY --from=builder /service /service\n"
        'CMD ["/service"]\n',
        encoding="utf-8",
    )

    assert manager.validate_custom_dockerfile(dockerfile) is None


def test_custom_lab_archive_rejects_traversal_paths(tmp_path):
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode="w:gz") as archive:
        member = tarfile.TarInfo("../outside")
        payload = b"not allowed"
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))

    with pytest.raises(ValueError, match="недопустимый путь"):
        manager.extract_custom_context(content.getvalue(), tmp_path)


def test_custom_lab_manager_endpoint_registers_only_a_verified_build(monkeypatch):
    image_ref = "cyberarena/custom-44:" + "c" * 20
    monkeypatch.setattr(
        manager,
        "build_custom_image",
        lambda *_args: image_ref,
    )
    monkeypatch.setattr(
        manager.app.state,
        "launch_secret",
        "manager-test-secret-that-is-at-least-32-characters",
        raising=False,
    )
    monkeypatch.setattr(manager.app.state, "materials", {}, raising=False)
    monkeypatch.setattr(manager.app.state, "custom_images", {}, raising=False)
    monkeypatch.setattr(manager.app.state, "docker", object(), raising=False)
    archive = custom_archive("FROM local-base\nCMD true\n")

    response = TestClient(manager.app).post(
        "/internal/custom-labs/44/build",
        data={"flag": "CTF{custom}"},
        files={"archive": ("custom.tar.gz", archive, "application/gzip")},
        headers={
            "X-Lab-Manager-Secret": "manager-test-secret-that-is-at-least-32-characters"
        },
    )

    assert response.status_code == 200
    assert response.json() == {"image_ref": image_ref, "status": "ready"}
    assert manager.app.state.custom_images == {}
    assert manager.app.state.materials == {}


def test_manager_requests_rebuild_when_registered_custom_image_is_missing(monkeypatch):
    class MissingImage:
        def get(self, _reference):
            raise manager.ImageNotFound("missing")

    class FakeDocker:
        images = MissingImage()

    monkeypatch.setattr(
        manager.app.state,
        "materials_secret",
        "manager-test-secret-that-is-at-least-32-characters",
        raising=False,
    )
    monkeypatch.setattr(manager.app.state, "docker", FakeDocker(), raising=False)
    monkeypatch.setattr(manager.app.state, "materials", {}, raising=False)
    monkeypatch.setattr(manager.app.state, "custom_images", {}, raising=False)
    request = manager.Request(
        {
            "type": "http",
            "method": "PUT",
            "path": "/internal/materials",
            "headers": [],
            "app": manager.app,
        }
    )
    update = manager.MaterialUpdate.model_validate(
        {
            "materials": {"custom-46": "CTF{custom}"},
            "custom_images": {"custom-46": "cyberarena/custom-46:" + "d" * 20},
        }
    )

    with pytest.raises(HTTPException) as error:
        manager.update_materials(
            update,
            request,
            secret="manager-test-secret-that-is-at-least-32-characters",
        )

    assert error.value.status_code == 409
    assert error.value.detail == {"missing_custom_images": ["custom-46"]}


def test_custom_lab_health_probe_uses_nginx_session_route(monkeypatch):
    urls = []
    removed = []

    class FakeContainer:
        labels = {}
        status = "exited"

        def remove(self, force):
            removed.append(force)

    class FakeContainers:
        def get(self, name):
            assert name == "ctf_lab_0_custom_45"
            return FakeContainer()

        def list(self, **_kwargs):
            return []

    class FakeNetworks:
        def list(self, **_kwargs):
            return []

    class FakeClient:
        containers = FakeContainers()
        networks = FakeNetworks()

    class FakeResponse:
        status_code = 200

    monkeypatch.setattr(
        manager,
        "create_lab",
        lambda *_args: ("e" * 43, False),
    )
    monkeypatch.setattr(
        manager.httpx,
        "get",
        lambda url, **_kwargs: (urls.append(url) or FakeResponse()),
    )
    manager.verify_custom_image(
        FakeClient(),
        "cyberarena/custom-45:" + "f" * 20,
        "custom-45",
        "CTF{custom}",
    )

    assert urls == ["http://nginx/lab-session/" + "e" * 43 + "/health"]
    assert removed == [True]
