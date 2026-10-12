from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.platform.services.scoreboard import get_scoreboard
from app.platform.storage import get_db

router = APIRouter()


@router.get("/api/scoreboard")
async def scoreboard(db: AsyncSession = Depends(get_db)) -> list[dict]:
    return await get_scoreboard(db)
