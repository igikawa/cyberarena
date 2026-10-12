from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.platform.dependencies import current_user, optional_user, require_csrf
from app.platform.models import Challenge, Solve, User
from app.platform.schemas import FlagSubmission
from app.platform.services.challenges import public_challenge, submit_flag
from app.platform.storage import get_db

router = APIRouter()


@router.get("/api/challenges")
async def list_challenges(
    user: User | None = Depends(optional_user), db: AsyncSession = Depends(get_db)
) -> list[dict]:
    challenges = (await db.scalars(select(Challenge).where(Challenge.is_published.is_(True)).order_by(Challenge.id))).all()
    solved_ids: set[int] = set()
    if user is not None:
        solved_ids = set((await db.scalars(select(Solve.challenge_id).where(Solve.user_id == user.id))).all())
    return [public_challenge(challenge, challenge.id in solved_ids) for challenge in challenges]


@router.get("/api/challenges/{challenge_id}")
async def challenge_detail(
    challenge_id: int,
    user: User | None = Depends(optional_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    challenge = await db.scalar(select(Challenge).where(Challenge.id == challenge_id, Challenge.is_published.is_(True)))
    if challenge is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    solved = user is not None and await db.scalar(
        select(Solve.id).where(Solve.user_id == user.id, Solve.challenge_id == challenge.id)
    ) is not None
    return public_challenge(challenge, bool(solved))


@router.post("/api/challenges/{challenge_id}/submit", dependencies=[Depends(require_csrf)])
async def submit(
    challenge_id: int,
    data: FlagSubmission,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    return await submit_flag(db, user, challenge_id, data.flag)
