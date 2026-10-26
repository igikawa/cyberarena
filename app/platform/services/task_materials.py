import httpx

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.platform.core.config import get_settings
from app.platform.core.security import decrypt_flag
from app.platform.models import Challenge

LAB_SEED_KEYS = (
    "web-01",
    "web-03-sqli",
    "web-04-path-traversal",
    "business-01",
    "reverse-01",
    "pwn-01",
)
LAB_MATERIALS_HTTP_TIMEOUT = httpx.Timeout(
    connect=3.0,
    read=60.0,
    write=10.0,
    pool=3.0,
)


def create_lab_material_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=LAB_MATERIALS_HTTP_TIMEOUT)


async def get_seeded_flag(db: AsyncSession, seed_key: str) -> str:
    challenge = await db.scalar(select(Challenge).where(Challenge.seed_key == seed_key))
    if challenge is None or challenge.flag_encrypted is None:
        raise HTTPException(status_code=503, detail="Challenge material is unavailable")
    return decrypt_flag(challenge.flag_encrypted)


async def refresh_lab_flags(db: AsyncSession) -> None:
    settings = get_settings()
    if not settings.lab_materials_url:
        return
    if settings.lab_materials_secret is None:
        raise HTTPException(status_code=503, detail="Laboratory materials synchronization is not configured")
    challenges = (
        await db.scalars(select(Challenge).where(Challenge.seed_key.in_(LAB_SEED_KEYS)))
    ).all()
    flags = {
        challenge.seed_key: decrypt_flag(challenge.flag_encrypted)
        for challenge in challenges
        if challenge.seed_key is not None and challenge.flag_encrypted is not None
    }
    try:
        async with create_lab_material_client() as client:
            response = await client.put(
                settings.lab_materials_url,
                json={"materials": flags},
                headers={"X-Lab-Materials-Secret": settings.lab_materials_secret},
            )
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail="Laboratory materials could not be synchronized",
        ) from exc
