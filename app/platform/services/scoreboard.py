from datetime import datetime

from fastapi.encoders import jsonable_encoder
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.platform.models import Challenge, Solve, User
from app.platform.services.cache import (
    SCOREBOARD_CACHE_KEY,
    delete_cache_keys,
    get_json_cache,
    set_json_cache,
)


def scoreboard_query():
    return (
        select(
            User.id.label("user_id"),
            User.username.label("username"),
            func.coalesce(func.sum(Challenge.points), 0).label("score"),
            func.max(Solve.solved_at).label("last_solve"),
        )
        .outerjoin(Solve, Solve.user_id == User.id)
        .outerjoin(Challenge, Challenge.id == Solve.challenge_id)
        .group_by(User.id, User.username)
        .order_by(func.coalesce(func.sum(Challenge.points), 0).desc(), func.max(Solve.solved_at).asc().nulls_last(), User.username.asc())
    )


async def get_scoreboard(db: AsyncSession, cache: Redis | None = None) -> list[dict]:
    cache_read = await get_json_cache(cache, SCOREBOARD_CACHE_KEY, list)
    cached = cache_read.value
    if isinstance(cached, list):
        try:
            for row in cached:
                if (
                    not isinstance(row, dict)
                    or not isinstance(row.get("user_id"), int)
                    or not isinstance(row.get("username"), str)
                    or not isinstance(row.get("score"), int)
                ):
                    raise ValueError("scoreboard entry must be an object")
                if isinstance(row.get("last_solve"), str):
                    row["last_solve"] = datetime.fromisoformat(row["last_solve"])
                elif row.get("last_solve") is not None:
                    raise ValueError("scoreboard timestamp must be a string or null")
        except ValueError:
            await delete_cache_keys(cache, SCOREBOARD_CACHE_KEY)
        else:
            return cached
    rows = (await db.execute(scoreboard_query())).all()
    result = [
        {"user_id": row.user_id, "username": row.username, "score": row.score, "last_solve": row.last_solve}
        for row in rows
    ]
    await set_json_cache(
        cache,
        SCOREBOARD_CACHE_KEY,
        jsonable_encoder(result),
        cache_read.generation,
    )
    return result
