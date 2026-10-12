from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.platform.models import Challenge, Solve, User


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


async def get_scoreboard(db: AsyncSession) -> list[dict]:
    rows = (await db.execute(scoreboard_query())).all()
    return [
        {"user_id": row.user_id, "username": row.username, "score": row.score, "last_solve": row.last_solve}
        for row in rows
    ]
