import httpx

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.platform.core.config import get_settings
from app.platform.core.security import decrypt_flag
from app.platform.models import Challenge
from app.platform.services.labs import LAB_CHALLENGE_KEYS, build_custom_lab

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
        await db.scalars(
            select(Challenge).where(
                (Challenge.seed_key.in_(LAB_CHALLENGE_KEYS))
                | (
                    (Challenge.lab_image_ref.is_not(None))
                    & (Challenge.lab_build_status == "ready")
                )
            )
        )
    ).all()
    flags = {
        challenge.seed_key or f"custom-{challenge.id}": decrypt_flag(challenge.flag_encrypted)
        for challenge in challenges
        if challenge.flag_encrypted is not None
    }
    custom_images = {
        f"custom-{challenge.id}": challenge.lab_image_ref
        for challenge in challenges
        if challenge.lab_image_ref is not None and challenge.lab_build_status == "ready"
    }
    try:
        async with create_lab_material_client() as client:
            response = await client.put(
                settings.lab_materials_url,
                json={"materials": flags, "custom_images": custom_images},
                headers={"X-Lab-Materials-Secret": settings.lab_materials_secret},
            )
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code != 409:
                    raise
                try:
                    detail = exc.response.json().get("detail", {})
                except (ValueError, AttributeError):
                    detail = {}
                missing = detail.get("missing_custom_images", []) if isinstance(detail, dict) else []
                by_key = {
                    f"custom-{challenge.id}": challenge
                    for challenge in challenges
                    if challenge.lab_image_ref is not None
                    and challenge.lab_build_status == "ready"
                }
                if (
                    not isinstance(missing, list)
                    or not missing
                    or any(key not in by_key for key in missing)
                ):
                    raise
                for key in missing:
                    challenge = by_key[key]
                    if challenge.lab_source_archive is None:
                        raise HTTPException(
                            status_code=503,
                            detail=f"Source archive for laboratory {key} is unavailable",
                        ) from exc
                    flags_for_build = flags.get(key)
                    if flags_for_build is None:
                        raise HTTPException(
                            status_code=503,
                            detail=f"Flag for laboratory {key} is unavailable",
                        ) from exc
                    challenge.lab_image_ref = await build_custom_lab(
                        challenge.id,
                        flags_for_build,
                        challenge.lab_source_archive,
                    )
                    custom_images[key] = challenge.lab_image_ref
                await db.commit()
                response = await client.put(
                    settings.lab_materials_url,
                    json={"materials": flags, "custom_images": custom_images},
                    headers={"X-Lab-Materials-Secret": settings.lab_materials_secret},
                )
                response.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail="Laboratory materials could not be synchronized",
        ) from exc
