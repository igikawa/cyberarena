import re

import httpx

from fastapi import HTTPException

from app.platform.core.config import get_settings
from app.platform.models import Challenge

LAB_CHALLENGE_KEYS = frozenset(
    {
        "web-01",
        "web-03-sqli",
        "web-04-path-traversal",
        "business-01",
        "reverse-01",
        "pwn-01",
    }
)

LAB_MANAGER_HTTP_TIMEOUT = httpx.Timeout(
    connect=3.0,
    read=60.0,
    write=10.0,
    pool=3.0,
)


def lab_key_for_challenge(challenge: Challenge) -> str | None:
    if challenge.seed_key is not None and challenge.seed_key in LAB_CHALLENGE_KEYS:
        return challenge.seed_key
    if challenge.lab_image_ref is not None and challenge.lab_build_status == "ready":
        return f"custom-{challenge.id}"
    return None


async def build_custom_lab(challenge_id: int, flag: str, archive: bytes) -> str:
    settings = get_settings()
    if not settings.lab_manager_url or not settings.lab_manager_secret:
        raise HTTPException(status_code=503, detail="User laboratories are unavailable")
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=3, read=300, write=30, pool=3)
        ) as client:
            response = await client.post(
                f"{settings.lab_manager_url.rstrip('/')}/internal/custom-labs/{challenge_id}/build",
                data={"flag": flag},
                files={"archive": ("source.tar.gz", archive, "application/gzip")},
                headers={"X-Lab-Manager-Secret": settings.lab_manager_secret},
            )
        response.raise_for_status()
        image_ref = response.json()["image_ref"]
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        detail = "A custom laboratory could not be built or verified"
        if isinstance(exc, httpx.HTTPStatusError):
            try:
                manager_detail = exc.response.json().get("detail")
            except ValueError:
                manager_detail = None
            if isinstance(manager_detail, str) and len(manager_detail) <= 300:
                detail = manager_detail
        raise HTTPException(status_code=503, detail=detail) from exc
    expected_prefix = f"cyberarena/custom-{challenge_id}:"
    if (
        not isinstance(image_ref, str)
        or not image_ref.startswith(expected_prefix)
        or re.fullmatch(r"cyberarena/custom-[1-9][0-9]*:[a-f0-9]{20}", image_ref) is None
    ):
        raise HTTPException(status_code=503, detail="Lab manager returned an invalid image reference")
    return image_ref


async def start_user_lab(user_id: int, challenge_key: str) -> str:
    settings = get_settings()
    if not settings.lab_manager_url or not settings.lab_manager_secret:
        raise HTTPException(status_code=503, detail="User laboratories are unavailable")
    try:
        async with httpx.AsyncClient(timeout=LAB_MANAGER_HTTP_TIMEOUT) as client:
            response = await client.post(
                f"{settings.lab_manager_url.rstrip('/')}/internal/labs",
                json={"user_id": user_id, "challenge_id": challenge_key},
                headers={"X-Lab-Manager-Secret": settings.lab_manager_secret},
            )
            response.raise_for_status()
            access_path = response.json()["access_path"]
    except (httpx.HTTPError, KeyError, ValueError) as exc:
        raise HTTPException(
            status_code=503,
            detail="A user laboratory could not be started",
        ) from exc
    if (
        not isinstance(access_path, str)
        or re.fullmatch(r"/lab-session/[A-Za-z0-9_-]{40,64}/", access_path) is None
    ):
        raise HTTPException(status_code=503, detail="Lab manager returned an invalid address")
    return access_path
