from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.platform.dependencies import current_user, optional_user, require_csrf
from app.platform.models import Challenge, Solve, User
from app.platform.schemas import FlagSubmission
from app.platform.services.challenges import get_published_challenges, submit_flag
from app.platform.services.labs import LAB_CHALLENGE_KEYS, start_user_lab
from app.platform.storage import get_db

router = APIRouter()
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


@router.get("/api/challenges")
async def list_challenges(
    request: Request,
    user: User | None = Depends(optional_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    challenges = await get_published_challenges(db, request.app.state.redis)
    solved_ids: set[int] = set()
    if user is not None:
        solved_ids = set((await db.scalars(select(Solve.challenge_id).where(Solve.user_id == user.id))).all())
    return [
        {**challenge, "is_solved": challenge["id"] in solved_ids}
        for challenge in challenges
    ]


@router.get("/api/challenges/{challenge_id}")
async def challenge_detail(
    challenge_id: int,
    request: Request,
    user: User | None = Depends(optional_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    challenge = next(
        (
            item
            for item in await get_published_challenges(db, request.app.state.redis)
            if item["id"] == challenge_id
        ),
        None,
    )
    if challenge is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    solved = user is not None and await db.scalar(
        select(Solve.id).where(Solve.user_id == user.id, Solve.challenge_id == challenge_id)
    ) is not None
    return {**challenge, "is_solved": bool(solved)}


@router.post("/api/challenges/{challenge_id}/submit", dependencies=[Depends(require_csrf)])
async def submit(
    challenge_id: int,
    data: FlagSubmission,
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    return await submit_flag(db, user, challenge_id, data.flag, request.app.state.redis)


@router.post(
    "/api/labs/{challenge_id}/start",
    dependencies=[Depends(require_csrf)],
)
async def start_lab_api(
    challenge_id: int,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    challenge = await db.get(Challenge, challenge_id)
    if challenge is None or not challenge.is_published:
        raise HTTPException(status_code=404, detail="Challenge not found")
    challenge_key = challenge.seed_key
    if (
        challenge_key is None
        or challenge_key not in LAB_CHALLENGE_KEYS
        or not challenge.resource_url
        or not challenge.resource_url.startswith("/lab/")
    ):
        raise HTTPException(status_code=400, detail="This challenge has no isolated lab")
    access_path = await start_user_lab(user.id, challenge_key)
    return {"access_path": access_path}
