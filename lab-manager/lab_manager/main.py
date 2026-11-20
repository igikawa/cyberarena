import hashlib
import io
import logging
import os
import re
import secrets
import threading
import tarfile
import tempfile
import time
from contextlib import asynccontextmanager
from pathlib import Path, PurePosixPath
from typing import Annotated

import docker
import httpx
from docker.errors import DockerException, ImageNotFound, NotFound
from docker.types import Ulimit
from fastapi import FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.concurrency import run_in_threadpool
from starlette.templating import Jinja2Templates

from lab_manager.metrics import (
    ACTIVE_LABS,
    DOCKER_UP,
    LAB_EXPIRATIONS,
    LAB_LAUNCH_DURATION,
    LAB_LAUNCHES,
    LAB_MATERIAL_UPDATES,
    LAB_REJECTIONS,
)

logger = logging.getLogger(__name__)

CHALLENGE_IMAGES: dict[str, str] = {
    "web-01": "web-01",
    "web-03-sqli": "web-03-sqli",
    "web-04-path-traversal": "web-04-path-traversal",
    "business-01": "business-01",
    "reverse-01": "reverse-01",
    "pwn-01": "pwn-01",
}
LAB_IMAGE_CONTEXT = Path("/opt/lab-build")
LAB_IMAGE_BUILD_REVISION = "4"
CUSTOM_LAB_BASE_IMAGE = "cyberarena/lab-base:custom"
LAB_CONTAINER_PORT = 8000
LAB_NETWORK_PREFIX = "ctf_lab_net_"
LAB_CONTAINER_PREFIX = "ctf_lab_"
MANAGED_LABEL = "cyberarena.managed"
OWNER_LABEL = "cyberarena.owner"
CHALLENGE_LABEL = "cyberarena.challenge"
EXPIRES_LABEL = "cyberarena.expires_at"
TOKEN_LABEL = "cyberarena.access_token"
NETWORK_LABEL = "cyberarena.network"
DOCKER_GATEWAY = os.getenv("DOCKER_GATEWAY", "172.31.250.3")
LAB_MEMORY_LIMIT = "128m"
LAB_NANO_CPUS = 250_000_000
LAB_PIDS_LIMIT = 64
LAB_NPROC_LIMIT = 10
MAX_CUSTOM_ARCHIVE_BYTES = 2 * 1024 * 1024
MAX_CUSTOM_CONTEXT_BYTES = 5 * 1024 * 1024
MAX_CUSTOM_CONTEXT_FILES = 100
CUSTOM_BUILD_TIMEOUT_SECONDS = 270
CUSTOM_BUILD_MEMORY_LIMIT = 1536 * 1024 * 1024
LAB_TTL_SECONDS = 900
LAB_READY_TIMEOUT_SECONDS = 30
LAB_READY_POLL_INTERVAL_SECONDS = 0.1
MAX_GLOBAL_LABS = 10
REAPER_INTERVAL_SECONDS = 15
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{40,64}$")
LAB_LAUNCH_LOCK = threading.RLock()
MATERIALS_LOCK = threading.RLock()
MATERIALS_UPDATE_LOCK = threading.Lock()
ALLOWED_MATERIAL_KEYS = frozenset(CHALLENGE_IMAGES)


class MaterialUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    materials: dict[str, Annotated[str, Field(min_length=1, max_length=256)]]
    custom_images: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def custom_materials_must_have_approved_images(self) -> "MaterialUpdate":
        custom_keys = {key for key in self.materials if key.startswith("custom-")}
        if any(
            key not in ALLOWED_MATERIAL_KEYS and re.fullmatch(r"custom-[1-9][0-9]*", key) is None
            for key in self.materials
        ):
            raise ValueError("Unknown laboratory material key")
        if set(self.custom_images) != custom_keys:
            raise ValueError("Every custom material must have exactly one approved image")
        for key, image_ref in self.custom_images.items():
            challenge_id = key.removeprefix("custom-")
            if re.fullmatch(
                rf"cyberarena/custom-{challenge_id}:[a-f0-9]{{20}}", image_ref
            ) is None:
                raise ValueError("Invalid custom laboratory image reference")
        return self


class LabLaunch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: int = Field(gt=0, le=2_147_483_647, strict=True)
    challenge_id: str = Field(min_length=1, max_length=64, strict=True)


def expected_secret(name: str) -> str:
    value = os.getenv(name, "")
    if len(value) < 32:
        raise RuntimeError(f"{name} must contain at least 32 characters")
    return value


def fingerprint_lab_image_context() -> str:
    digest = hashlib.sha256()
    digest.update(LAB_IMAGE_BUILD_REVISION.encode())
    for path in sorted(LAB_IMAGE_CONTEXT.rglob("*")):
        if path.is_file():
            digest.update(path.relative_to(LAB_IMAGE_CONTEXT).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()[:20]


def ensure_lab_images(client: docker.DockerClient) -> dict[str, str]:
    fingerprint = fingerprint_lab_image_context()
    base_image = f"cyberarena/lab-base:{fingerprint}"
    try:
        image = client.images.get(base_image)
    except ImageNotFound:
        client.images.build(
            path=str(LAB_IMAGE_CONTEXT),
            tag=base_image,
            rm=True,
            pull=False,
            nocache=True,
        )
        image = client.images.get(base_image)
    if not image.tag("cyberarena/lab-base", tag="custom", force=True):
        raise DockerException("Could not tag the approved custom lab base image")
    result = {}
    for challenge_id, image_name in CHALLENGE_IMAGES.items():
        tagged_image = f"cyberarena/{image_name}:{fingerprint}"
        try:
            client.images.get(tagged_image)
        except ImageNotFound:
            if not image.tag(
                f"cyberarena/{image_name}",
                tag=fingerprint,
                force=True,
            ):
                raise DockerException(f"Could not tag the approved image for {challenge_id}")
        result[challenge_id] = tagged_image
    return result


def extract_custom_context(archive: bytes, destination: Path) -> None:
    if not archive or len(archive) > MAX_CUSTOM_ARCHIVE_BYTES:
        raise ValueError("Архив исходников должен быть не больше 2 МиБ.")
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r|gz") as source:
            file_count = 0
            member_count = 0
            total_size = 0
            for member in source:
                member_count += 1
                if member_count > MAX_CUSTOM_CONTEXT_FILES:
                    raise ValueError("В архиве должно быть не больше 100 элементов.")
                member_path = PurePosixPath(member.name)
                if (
                    member_path.is_absolute()
                    or not member_path.parts
                    or any(part in {"", ".", ".."} for part in member_path.parts)
                    or not (member.isfile() or member.isdir())
                ):
                    raise ValueError("Архив содержит недопустимый путь или тип файла.")
                total_size += member.size if member.isfile() else 0
                if member.size < 0 or member.size > MAX_CUSTOM_CONTEXT_BYTES:
                    raise ValueError("Размер файла в архиве превышает лимит.")
                if total_size > MAX_CUSTOM_CONTEXT_BYTES:
                    raise ValueError("Распакованный архив превышает 5 МиБ.")
                target = destination.joinpath(*member_path.parts)
                target.resolve().relative_to(destination.resolve())
                if member.isdir():
                    if member.size:
                        raise ValueError("Каталог в архиве имеет недопустимый размер.")
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                file_count += 1
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = source.extractfile(member)
                if stream is None:
                    raise ValueError("Не удалось прочитать файл из архива.")
                with stream, target.open("wb") as output:
                    content = stream.read(member.size + 1)
                    if len(content) != member.size:
                        raise ValueError("Размер файла в архиве не соответствует заголовку.")
                    output.write(content)
                target.chmod(member.mode & 0o777)
            if not file_count or not (destination / "Dockerfile").is_file():
                raise ValueError("В корне архива должен находиться Dockerfile.")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ValueError("Не удалось прочитать tar.gz архив исходников.") from exc


def validate_custom_dockerfile(dockerfile: Path) -> None:
    try:
        text = dockerfile.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("Dockerfile должен быть корректным UTF-8 текстом.") from exc
    if not text.strip() or len(text.encode()) > 16 * 1024:
        raise ValueError("Dockerfile пустой или превышает 16 КиБ.")
    if re.search(r"(?im)^\s*FROM\s+\S+", text) is None:
        raise ValueError("Dockerfile должен содержать инструкцию FROM.")


def verify_custom_image(
    client: docker.DockerClient,
    image_ref: str,
    challenge_key: str,
    flag: str,
) -> None:
    token, _ = create_lab(client, image_ref, 0, challenge_key, flag)
    try:
        response = httpx.get(
            f"http://nginx/lab-session/{token}/health",
            timeout=httpx.Timeout(connect=3, read=5, write=3, pool=3),
        )
        if response.status_code != 200:
            raise DockerException(
                f"Laboratory proxy health check returned HTTP {response.status_code}"
            )
    except httpx.HTTPError as exc:
        raise DockerException("Laboratory was not reachable through the Nginx proxy") from exc
    finally:
        try:
            container = client.containers.get(
                f"{LAB_CONTAINER_PREFIX}0_{challenge_key.replace('-', '_')}"
            )
            remove_lab(client, container)
        except NotFound:
            pass
        remove_orphaned_networks(client)


def build_custom_image(
    client: docker.DockerClient,
    challenge_id: int,
    flag: str,
    archive: bytes,
) -> str:
    challenge_key = f"custom-{challenge_id}"
    image_ref = f"cyberarena/{challenge_key}:{hashlib.sha256(archive).hexdigest()[:20]}"
    with tempfile.TemporaryDirectory(prefix="cyberarena-custom-lab-") as directory:
        context = Path(directory)
        extract_custom_context(archive, context)
        validate_custom_dockerfile(context / "Dockerfile")
        built = False
        try:
            client.images.build(
                path=str(context),
                tag=image_ref,
                rm=True,
                forcerm=True,
                pull=False,
                nocache=True,
                network_mode="bridge",
                timeout=CUSTOM_BUILD_TIMEOUT_SECONDS,
                container_limits={
                    "memory": CUSTOM_BUILD_MEMORY_LIMIT,
                    "memswap": CUSTOM_BUILD_MEMORY_LIMIT,
                    "cpushares": 1024,
                },
            )
            built = True
            client.images.get(image_ref)
            verify_custom_image(client, image_ref, challenge_key, flag)
        except Exception:
            if built:
                try:
                    client.images.remove(image_ref, force=True)
                except (DockerException, ImageNotFound):
                    logger.exception("Could not remove failed custom lab image %s", image_ref)
            raise
    return image_ref


def get_managed_containers(client: docker.DockerClient):
    return client.containers.list(
        all=True,
        filters={"label": f"{MANAGED_LABEL}=true"},
    )


def remove_lab(client: docker.DockerClient, container) -> None:
    labels = container.labels
    network_name = labels.get(NETWORK_LABEL)
    try:
        container.remove(force=True)
    except NotFound:
        pass
    if network_name:
        try:
            client.networks.get(network_name).remove()
        except NotFound:
            pass
    ACTIVE_LABS.set(
        sum(1 for item in get_managed_containers(client) if item.status == "running")
    )


def remove_orphaned_networks(client: docker.DockerClient) -> None:
    used_networks = {
        container.labels.get(NETWORK_LABEL)
        for container in get_managed_containers(client)
    }
    networks = client.networks.list(
        filters={"label": f"{MANAGED_LABEL}=true"},
    )
    for network in networks:
        if network.name not in used_networks:
            try:
                network.remove()
            except NotFound:
                pass


def remove_expired_labs(client: docker.DockerClient) -> None:
    with LAB_LAUNCH_LOCK:
        now = time.time()
        for container in get_managed_containers(client):
            try:
                expires_at = float(container.labels.get(EXPIRES_LABEL, "0"))
            except ValueError:
                expires_at = 0
            if container.status != "running" or expires_at <= now:
                was_expired = expires_at <= now
                remove_lab(client, container)
                if was_expired:
                    LAB_EXPIRATIONS.inc()
        remove_orphaned_networks(client)


def lab_target(client: docker.DockerClient, token: str) -> str | None:
    with LAB_LAUNCH_LOCK:
        if not TOKEN_PATTERN.fullmatch(token):
            return None
        containers = client.containers.list(
            all=False,
            filters={
                "label": [
                    f"{MANAGED_LABEL}=true",
                    f"{TOKEN_LABEL}={token}",
                ]
            },
        )
        if len(containers) != 1:
            return None
        container = containers[0]
        try:
            if float(container.labels.get(EXPIRES_LABEL, "0")) <= time.time():
                remove_lab(client, container)
                LAB_EXPIRATIONS.inc()
                return None
        except ValueError:
            remove_lab(client, container)
            return None
        container.reload()
        bindings = container.attrs.get("NetworkSettings", {}).get("Ports", {}).get(
            f"{LAB_CONTAINER_PORT}/tcp"
        )
        if not bindings:
            return None
        return f"http://{DOCKER_GATEWAY}:{bindings[0]['HostPort']}"


def lab_is_ready(target: str) -> bool:
    try:
        return httpx.get(target, timeout=0.5).status_code == 200
    except httpx.HTTPError:
        return False


def create_lab(
    client: docker.DockerClient,
    image: str,
    user_id: int,
    challenge_id: str,
    flag: str,
) -> tuple[str, bool]:
    with LAB_LAUNCH_LOCK:
        remove_expired_labs(client)
        container_name = (
            f"{LAB_CONTAINER_PREFIX}{user_id}_{challenge_id.replace('-', '_')}"
        )
        try:
            existing = client.containers.get(container_name)
        except NotFound:
            existing = None
        if existing is not None:
            token = existing.labels.get(TOKEN_LABEL)
            if (
                existing.status == "running"
                and token is not None
                and TOKEN_PATTERN.fullmatch(token)
            ):
                return token, True
            remove_lab(client, existing)

        for candidate in get_managed_containers(client):
            if candidate.labels.get(OWNER_LABEL) == str(user_id):
                remove_lab(client, candidate)

        running = [
            item for item in get_managed_containers(client) if item.status == "running"
        ]
        if len(running) >= MAX_GLOBAL_LABS:
            LAB_REJECTIONS.labels(reason="global_quota").inc()
            raise HTTPException(
                status_code=429,
                detail="All laboratory slots are currently in use",
            )

        token = secrets.token_urlsafe(32)
        network_suffix = hashlib.sha256(
            f"{user_id}:{challenge_id}".encode()
        ).hexdigest()[:16]
        network_name = f"{LAB_NETWORK_PREFIX}{network_suffix}"
        expires_at = time.time() + LAB_TTL_SECONDS
        labels = {
            MANAGED_LABEL: "true",
            OWNER_LABEL: str(user_id),
            CHALLENGE_LABEL: challenge_id,
            EXPIRES_LABEL: str(expires_at),
            TOKEN_LABEL: token,
            NETWORK_LABEL: network_name,
        }
        network = None
        container = None
        try:
            network = client.networks.create(
                network_name,
                driver="bridge",
                internal=False,
                enable_ipv6=False,
                check_duplicate=True,
                options={
                    "com.docker.network.bridge.enable_ip_masquerade": "false",
                    "com.docker.network.bridge.enable_icc": "false",
                },
                labels=labels,
            )
            container_options = {
                "image": image,
                "name": container_name,
                "init": True,
                "runtime": "runsc",
                "network": network.name,
                "ports": {
                    f"{LAB_CONTAINER_PORT}/tcp": (DOCKER_GATEWAY, None)
                },
                "environment": {
                    "LAB_CHALLENGE_KEY": challenge_id,
                    "LAB_CHALLENGE_FLAG": flag,
                },
                "labels": labels,
                "mem_limit": LAB_MEMORY_LIMIT,
                "memswap_limit": LAB_MEMORY_LIMIT,
                "nano_cpus": LAB_NANO_CPUS,
                "pids_limit": LAB_PIDS_LIMIT,
                "ulimits": [
                    Ulimit(
                        name="nproc",
                        soft=LAB_NPROC_LIMIT,
                        hard=LAB_NPROC_LIMIT,
                    )
                ],
                "restart_policy": {"Name": "no"},
            }
            if not challenge_id.startswith("custom-"):
                container_options.update(
                    {
                        "user": "10001:10001",
                        "read_only": True,
                        "cap_drop": ["ALL"],
                        "security_opt": ["no-new-privileges=true"],
                        "tmpfs": {"/tmp": "rw,noexec,nosuid,size=16m"},
                    }
                )
            container = client.containers.create(**container_options)
            container.start()
            deadline = time.monotonic() + LAB_READY_TIMEOUT_SECONDS
            published_port = False
            while time.monotonic() < deadline:
                container.reload()
                bindings = container.attrs.get("NetworkSettings", {}).get(
                    "Ports", {}
                ).get(f"{LAB_CONTAINER_PORT}/tcp")
                if container.status == "running" and bindings:
                    published_port = True
                    target = f"http://{DOCKER_GATEWAY}:{bindings[0]['HostPort']}/health"
                    if lab_is_ready(target):
                        ACTIVE_LABS.set(len(running) + 1)
                        return token, False
                time.sleep(LAB_READY_POLL_INTERVAL_SECONDS)
            raise DockerException(
                "Laboratory did not become ready within "
                f"{LAB_READY_TIMEOUT_SECONDS}s "
                f"(container_status={container.status}, "
                f"port_published={published_port})"
            )
        except Exception:
            if container is not None:
                try:
                    container.remove(force=True)
                except NotFound:
                    pass
            if network is not None:
                try:
                    network.remove()
                except NotFound:
                    pass
            raise


def reaper_loop(manager: FastAPI, stop_event: threading.Event) -> None:
    while not stop_event.wait(REAPER_INTERVAL_SECONDS):
        try:
            remove_expired_labs(manager.state.docker)
        except DockerException:
            logger.exception("Could not reap expired lab containers")


@asynccontextmanager
async def lifespan(manager: FastAPI):
    launch_secret = expected_secret("LAB_MANAGER_SECRET")
    materials_secret = expected_secret("LAB_MATERIALS_SECRET")
    client = docker.from_env(timeout=10)
    try:
        client.ping()
        runtimes = client.info().get("Runtimes", {})
        if "runsc" not in runtimes:
            raise RuntimeError("The isolated Docker daemon does not provide the runsc runtime")
        manager.state.docker = client
        manager.state.lab_images = await run_in_threadpool(ensure_lab_images, client)
        manager.state.launch_secret = launch_secret
        manager.state.materials_secret = materials_secret
        manager.state.materials = {}
        manager.state.custom_images = {}
        remove_expired_labs(client)
        ACTIVE_LABS.set(
            sum(
                1
                for item in get_managed_containers(client)
                if item.status == "running"
            )
        )
        manager.state.reaper_stop = threading.Event()
        manager.state.reaper = threading.Thread(
            target=reaper_loop,
            args=(manager, manager.state.reaper_stop),
            name="lab-ttl-reaper",
            daemon=True,
        )
        manager.state.reaper.start()
        manager.state.docker_ready = True
        DOCKER_UP.set(1)
        yield
    except Exception:
        DOCKER_UP.set(0)
        client.close()
        raise
    finally:
        if hasattr(manager.state, "reaper_stop"):
            manager.state.reaper_stop.set()
            manager.state.reaper.join(timeout=2)
        manager.state.docker_ready = False
        DOCKER_UP.set(0)
        client.close()


app = FastAPI(
    title="CYBERARENA Lab Manager",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
error_templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))


def wants_lab_html_error(request: Request) -> bool:
    if not request.url.path.startswith("/lab-session/"):
        return False
    accepted_types: dict[str, float] = {}
    for accepted_type in request.headers.get("accept", "").split(","):
        media_type, *parameters = accepted_type.strip().lower().split(";")
        quality = 1.0
        for parameter in parameters:
            name, separator, value = parameter.strip().partition("=")
            if name == "q" and separator:
                try:
                    quality = float(value)
                except ValueError:
                    quality = 0.0
                break
        accepted_types[media_type] = quality
    html_quality = accepted_types.get("text/html", 0.0)
    json_quality = accepted_types.get("application/json", 0.0)
    return html_quality > 0 and html_quality > json_quality


def render_lab_error(
    request: Request,
    status_code: int,
    headers: dict | None = None,
) -> HTMLResponse:
    if status_code == 404:
        eyebrow = "Сессия лаборатории завершена"
        title = "Лаборатория больше недоступна"
        message = (
            "Время работы лаборатории истекло или ссылка неверна. "
            "Сессия лаборатории действует ограниченное время."
        )
        hint = "Вернитесь к заданию и запустите новую личную лабораторию. Ваш прогресс на платформе сохранён."
    elif status_code == 503:
        eyebrow = "Временный сбой лаборатории"
        title = "Не удалось открыть лабораторию"
        message = (
            "Лаборатория временно недоступна: контейнер может запускаться, "
            "перезапускаться или быть занят."
        )
        hint = "Подождите немного и попробуйте снова со страницы задания. Ваши результаты на платформе не потеряны."
    else:
        eyebrow = "Ошибка лаборатории"
        title = "Не удалось выполнить запрос"
        message = "Проверьте ссылку и попробуйте открыть задание ещё раз."
        hint = "Если ошибка повторяется, обратитесь к преподавателю или администратору турнира."
    return error_templates.TemplateResponse(
        request,
        "lab_error.html",
        {
            "status_code": status_code,
            "eyebrow": eyebrow,
            "title": title,
            "message": message,
            "hint": hint,
        },
        status_code=status_code,
        headers={"Cache-Control": "no-store", **(headers or {})},
    )


@app.exception_handler(StarletteHTTPException)
async def lab_http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> HTMLResponse | JSONResponse:
    if wants_lab_html_error(request):
        return render_lab_error(request, exc.status_code, exc.headers)
    return JSONResponse(
        status_code=exc.status_code,
        content=jsonable_encoder({"detail": exc.detail}),
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def lab_validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> HTMLResponse | JSONResponse:
    if wants_lab_html_error(request):
        return render_lab_error(request, 422)
    return JSONResponse(status_code=422, content=jsonable_encoder({"detail": exc.errors()}))


def authenticate(secret: str | None, expected: str) -> None:
    if secret is None or not secrets.compare_digest(secret, expected):
        raise HTTPException(status_code=401, detail="Invalid service credentials")


@app.get("/health", include_in_schema=False)
def health(request: Request) -> dict[str, str]:
    try:
        request.app.state.docker.ping()
        if "runsc" not in request.app.state.docker.info().get("Runtimes", {}):
            raise DockerException("The runsc runtime is unavailable")
    except DockerException as exc:
        request.app.state.docker_ready = False
        DOCKER_UP.set(0)
        raise HTTPException(
            status_code=503, detail="Docker sandbox is unavailable"
        ) from exc
    request.app.state.docker_ready = True
    DOCKER_UP.set(1)
    return {"status": "ok"}


@app.get("/metrics", include_in_schema=False)
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/internal/custom-labs/{challenge_id}/build", include_in_schema=False)
async def build_custom_lab(
    challenge_id: int,
    request: Request,
    flag: Annotated[str, Form(min_length=1, max_length=256)],
    archive: UploadFile = File(...),
    secret: Annotated[str | None, Header(alias="X-Lab-Manager-Secret")] = None,
) -> dict[str, str]:
    authenticate(secret, request.app.state.launch_secret)
    if challenge_id < 1:
        raise HTTPException(status_code=422, detail="Invalid challenge ID")
    archive_bytes = await archive.read(MAX_CUSTOM_ARCHIVE_BYTES + 1)
    try:
        image_ref = await run_in_threadpool(
            build_custom_image,
            request.app.state.docker,
            challenge_id,
            flag,
            archive_bytes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except DockerException as exc:
        logger.exception("Custom lab build or readiness check failed for challenge %s", challenge_id)
        raise HTTPException(
            status_code=503,
            detail="Сборка или проверка лаборатории не прошла. Проверьте Dockerfile, /health и логи lab-manager.",
        ) from exc
    return {"image_ref": image_ref, "status": "ready"}


@app.put("/internal/materials", include_in_schema=False)
def update_materials(
    update: MaterialUpdate,
    request: Request,
    secret: Annotated[str | None, Header(alias="X-Lab-Materials-Secret")] = None,
) -> dict[str, str]:
    authenticate(secret, request.app.state.materials_secret)
    new_materials = dict(update.materials)
    new_custom_images = dict(update.custom_images)
    with MATERIALS_UPDATE_LOCK:
        with MATERIALS_LOCK:
            if (
                request.app.state.materials == new_materials
                and getattr(request.app.state, "custom_images", {}) == new_custom_images
            ):
                return {"status": "updated"}
        missing_images = []
        for challenge_key, image_ref in new_custom_images.items():
            try:
                request.app.state.docker.images.get(image_ref)
            except ImageNotFound:
                missing_images.append(challenge_key)
        if missing_images:
            raise HTTPException(
                status_code=409,
                detail={"missing_custom_images": missing_images},
            )
        with LAB_LAUNCH_LOCK:
            with MATERIALS_LOCK:
                previous_materials = request.app.state.materials
                previous_custom_images = getattr(request.app.state, "custom_images", {})
                changed_challenges = {
                    key
                    for key in set(previous_materials) | set(new_materials)
                    if previous_materials.get(key) != new_materials.get(key)
                    or previous_custom_images.get(key) != new_custom_images.get(key)
                }
                request.app.state.materials = new_materials
                request.app.state.custom_images = new_custom_images
            if changed_challenges:
                for container in get_managed_containers(request.app.state.docker):
                    challenge = container.labels.get(CHALLENGE_LABEL)
                    if challenge in changed_challenges:
                        remove_lab(request.app.state.docker, container)
                        LAB_MATERIAL_UPDATES.labels(challenge=challenge).inc()
                retired_images = set(previous_custom_images.values()) - set(new_custom_images.values())
                for image_ref in retired_images:
                    try:
                        request.app.state.docker.images.remove(image_ref)
                    except ImageNotFound:
                        pass
                    except DockerException:
                        logger.exception("Could not remove retired custom lab image %s", image_ref)
    return {"status": "updated"}


@app.post("/internal/labs", include_in_schema=False)
def start_lab(
    launch: LabLaunch,
    request: Request,
    secret: Annotated[str | None, Header(alias="X-Lab-Manager-Secret")] = None,
) -> dict[str, str]:
    authenticate(secret, request.app.state.launch_secret)
    challenge_id = launch.challenge_id
    if challenge_id in CHALLENGE_IMAGES:
        image_ref = request.app.state.lab_images[challenge_id]
    elif re.fullmatch(r"custom-[1-9][0-9]*", challenge_id):
        image_ref = getattr(request.app.state, "custom_images", {}).get(challenge_id)
        if image_ref is None:
            raise HTTPException(status_code=400, detail="Challenge has no approved lab image")
    else:
        raise HTTPException(status_code=400, detail="Challenge has no approved lab image")
    started = time.perf_counter()
    try:
        with LAB_LAUNCH_LOCK:
            with MATERIALS_LOCK:
                flag = request.app.state.materials.get(challenge_id)
            if not flag:
                LAB_REJECTIONS.labels(reason="material_unavailable").inc()
                raise HTTPException(
                    status_code=503,
                    detail="Challenge material is not synchronized",
                )
            token, reused = create_lab(
                request.app.state.docker,
                image_ref,
                launch.user_id,
                challenge_id,
                flag,
            )
        LAB_LAUNCHES.labels(
            challenge=challenge_id,
            result="reused" if reused else "started",
        ).inc()
        return {"access_path": f"/lab-session/{token}/"}
    except HTTPException:
        LAB_LAUNCHES.labels(challenge=challenge_id, result="rejected").inc()
        raise
    except DockerException as exc:
        LAB_LAUNCHES.labels(challenge=challenge_id, result="error").inc()
        LAB_REJECTIONS.labels(reason="docker_error").inc()
        logger.exception("Could not start an isolated lab for an allowed challenge")
        raise HTTPException(
            status_code=503,
            detail="Laboratory could not be started",
        ) from exc
    finally:
        LAB_LAUNCH_DURATION.labels(challenge=challenge_id).observe(
            time.perf_counter() - started
        )


@app.api_route(
    "/lab-session/{token}/{subpath:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    include_in_schema=False,
)
async def proxy_lab(
    token: str,
    subpath: str,
    request: Request,
) -> Response:
    target = await run_in_threadpool(
        lab_target,
        request.app.state.docker,
        token,
    )
    if target is None:
        raise HTTPException(status_code=404, detail="Laboratory session has expired")
    url = httpx.URL(f"{target}/{subpath}").copy_with(query=request.url.query.encode())
    forward_headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() in {"accept", "content-type", "cookie", "user-agent", "referer"}
    }
    forward_headers["X-Lab-Base-Path"] = f"/lab-session/{token}"
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=3, read=30, write=30, pool=3),
            follow_redirects=False,
        ) as client:
            upstream = await client.request(
                request.method,
                url,
                headers=forward_headers,
                content=await request.body(),
            )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail="Laboratory is temporarily unavailable",
        ) from exc

    response_headers = {
        key: value
        for key, value in upstream.headers.items()
        if key.lower()
        in {"content-type", "cache-control", "content-disposition", "location"}
    }
    location = response_headers.get("location")
    if location and location.startswith("/") and not location.startswith("//"):
        response_headers["location"] = f"/lab-session/{token}{location}"
    response_headers["Cache-Control"] = "no-store"
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=response_headers,
    )
