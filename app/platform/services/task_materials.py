import json
import os
import tempfile
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.platform.core.config import get_settings
from app.platform.core.security import decrypt_flag
from app.platform.models import Challenge


async def get_seeded_flag(db: AsyncSession, seed_key: str) -> str:
    challenge = await db.scalar(select(Challenge).where(Challenge.seed_key == seed_key))
    if challenge is None or challenge.flag_encrypted is None:
        raise HTTPException(status_code=503, detail="Challenge material is unavailable")
    return decrypt_flag(challenge.flag_encrypted)


async def refresh_lab_flags(db: AsyncSession) -> None:
    challenge = await db.scalar(select(Challenge).where(Challenge.seed_key == "web-01"))
    flags = (
        {"web-01": decrypt_flag(challenge.flag_encrypted)}
        if challenge is not None and challenge.flag_encrypted is not None
        else {}
    )
    target = get_settings().lab_flags_file
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=target.parent,
        prefix=".lab-flags-",
        delete=False,
    )
    temporary_path = Path(temporary.name)
    try:
        with temporary:
            json.dump(flags, temporary)
            temporary.write("\n")
        os.replace(temporary_path, target)
    finally:
        temporary_path.unlink(missing_ok=True)
