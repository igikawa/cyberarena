from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
import pandas as pd
from starlette.responses import Response

from app.platform.dependencies import admin_user, require_csrf
from app.platform.models import Challenge, Solve, Submission, User
from app.platform.schemas import ChallengeInput, ChallengePatch
from app.platform.services.challenges import (
    create_challenge as create_challenge_record,
    delete_challenge as delete_challenge_record,
    update_challenge as update_challenge_record,
    validate_resource_url,
)
from app.platform.services.scoreboard import get_scoreboard
from app.platform.storage import get_db

router = APIRouter(prefix="/api/admin", dependencies=[Depends(admin_user)])


def admin_challenge_view(challenge: Challenge) -> dict:
    return {
        "id": challenge.id,
        "title": challenge.title,
        "category": challenge.category,
        "description": challenge.description,
        "points": challenge.points,
        "is_published": challenge.is_published,
        "resource_url": challenge.resource_url,
        "created_at": challenge.created_at,
        "updated_at": challenge.updated_at,
    }


@router.get("/challenges")
async def list_all_challenges(db: AsyncSession = Depends(get_db)) -> list[dict]:
    values = (await db.scalars(select(Challenge).order_by(Challenge.id))).all()
    return [admin_challenge_view(value) for value in values]


@router.post("/challenges", status_code=201, dependencies=[Depends(require_csrf)])
async def create_challenge(data: ChallengeInput, db: AsyncSession = Depends(get_db)) -> dict:
    challenge = await create_challenge_record(db, data)
    return admin_challenge_view(challenge)


@router.get("/challenges/{challenge_id}")
async def get_challenge(challenge_id: int, db: AsyncSession = Depends(get_db)) -> dict:
    challenge = await db.get(Challenge, challenge_id)
    if challenge is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    return admin_challenge_view(challenge)


@router.patch("/challenges/{challenge_id}", dependencies=[Depends(require_csrf)])
async def update_challenge(challenge_id: int, data: ChallengePatch, db: AsyncSession = Depends(get_db)) -> dict:
    challenge = await db.get(Challenge, challenge_id)
    if challenge is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    challenge = await update_challenge_record(db, challenge, data)
    return admin_challenge_view(challenge)


@router.delete("/challenges/{challenge_id}", status_code=204, dependencies=[Depends(require_csrf)])
async def delete_challenge(challenge_id: int, db: AsyncSession = Depends(get_db)) -> None:
    challenge = await db.get(Challenge, challenge_id)
    if challenge is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    await delete_challenge_record(db, challenge)


async def set_published(challenge_id: int, published: bool, db: AsyncSession) -> dict:
    challenge = await db.get(Challenge, challenge_id)
    if challenge is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    challenge.is_published = published
    await db.commit()
    return {"id": challenge.id, "is_published": published}


@router.post("/challenges/{challenge_id}/publish", dependencies=[Depends(require_csrf)])
async def publish_challenge(challenge_id: int, db: AsyncSession = Depends(get_db)) -> dict:
    return await set_published(challenge_id, True, db)


@router.post("/challenges/{challenge_id}/unpublish", dependencies=[Depends(require_csrf)])
async def unpublish_challenge(challenge_id: int, db: AsyncSession = Depends(get_db)) -> dict:
    return await set_published(challenge_id, False, db)


@router.get("/submissions")
async def submissions(
    limit: int = Query(default=100, ge=1, le=500), db: AsyncSession = Depends(get_db)
) -> list[dict]:
    rows = (
        await db.execute(
            select(Submission, User.username, Challenge.title)
            .join(User, User.id == Submission.user_id)
            .join(Challenge, Challenge.id == Submission.challenge_id)
            .order_by(Submission.submitted_at.desc())
            .limit(limit)
        )
    ).all()
    return [
        {"id": s.id, "username": username, "challenge_id": s.challenge_id, "challenge_title": title,
         "submitted_at": s.submitted_at, "is_correct": s.is_correct}
        for s, username, title in rows
    ]


@router.get("/solves")
async def solves(limit: int = Query(default=100, ge=1, le=500), db: AsyncSession = Depends(get_db)) -> list[dict]:
    rows = (
        await db.execute(
            select(Solve, User.username, Challenge.title)
            .join(User, User.id == Solve.user_id)
            .join(Challenge, Challenge.id == Solve.challenge_id)
            .order_by(Solve.solved_at.desc())
            .limit(limit)
        )
    ).all()
    return [
        {"id": solve.id, "username": username, "challenge_id": solve.challenge_id,
         "challenge_title": title, "solved_at": solve.solved_at}
        for solve, username, title in rows
    ]


@router.get("/scoreboard")
async def admin_scoreboard(db: AsyncSession = Depends(get_db)) -> list[dict]:
    return await get_scoreboard(db)


@router.get("/csvscoreboard")
async def admin_csv_scoreboard(db: AsyncSession = Depends(get_db)) -> Response:
    data = await get_scoreboard(db)
    df = pd.DataFrame(data)
    return Response(
        content=df.to_csv(index=False),
        media_type="text/csv; charset=utf-8",
        headers={
            "Cache-Control": "no-store",
            "Content-Disposition": 'attachment; filename="admin_scoreboard.csv"',
        },
    )

@router.post("/tournament/reset", dependencies=[Depends(require_csrf)])
async def reset_tournament(db: AsyncSession = Depends(get_db)) -> dict[str, int]:
    submission_result = await db.execute(delete(Submission))
    solve_result = await db.execute(delete(Solve))
    await db.commit()
    return {"submissions_deleted": submission_result.rowcount or 0, "solves_deleted": solve_result.rowcount or 0}
