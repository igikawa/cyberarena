import re

import httpx

from fastapi import HTTPException

from app.platform.core.config import get_settings

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
