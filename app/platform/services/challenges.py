from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.platform.core.security import encrypt_flag, hash_flag, verify_flag
from app.platform.models import Challenge, DeletedChallengeSeed, Solve, Submission, User
from app.platform.metrics import FLAG_SUBMISSIONS, SOLVES_AWARDED
from app.platform.schemas import ChallengeInput, ChallengePatch, validate_flag_value
from app.platform.services.cache import (
    CHALLENGES_CACHE_KEY,
    delete_cache_keys,
    get_json_cache,
    invalidate_challenges_cache,
    invalidate_scoreboard_cache,
    set_json_cache,
)


def validate_resource_url(url: str | None) -> None:
    if url and not (
        (url.startswith("/") and not url.startswith("//"))
        or url.startswith("https://")
        or url.startswith("http://")
    ):
        raise HTTPException(status_code=422, detail="Resource URL must be a relative path or HTTP(S) URL")


async def create_challenge(
    db: AsyncSession, data: ChallengeInput, cache: Redis | None = None
) -> Challenge:
    validate_resource_url(data.resource_url)
    challenge = Challenge(
        title=data.title.strip(),
        category=data.category.strip(),
        description=data.description.strip(),
        points=data.points,
        flag_hash=hash_flag(data.flag),
        flag_encrypted=encrypt_flag(data.flag),
        is_published=data.is_published,
        resource_url=data.resource_url,
    )
    db.add(challenge)
    await db.commit()
    await db.refresh(challenge)
    await invalidate_challenges_cache(cache)
    return challenge


async def update_challenge(
    db: AsyncSession, challenge: Challenge, data: ChallengePatch, cache: Redis | None = None
) -> Challenge:
    changes = data.model_dump(exclude_unset=True)
    flag = changes.pop("flag", None)
    if "resource_url" in changes:
        validate_resource_url(changes["resource_url"])
    for key, value in changes.items():
        setattr(challenge, key, value.strip() if isinstance(value, str) and key != "resource_url" else value)
    if flag:
        challenge.flag_hash = hash_flag(flag)
        challenge.flag_encrypted = encrypt_flag(flag)
    await db.commit()
    await db.refresh(challenge)
    await invalidate_challenges_cache(cache)
    await invalidate_scoreboard_cache(cache)
    if flag and challenge.seed_key in {
        "web-01",
        "web-03-sqli",
        "web-04-path-traversal",
        "business-01",
        "reverse-01",
        "pwn-01",
    }:
        from app.platform.services.task_materials import refresh_lab_flags

        await refresh_lab_flags(db)
    return challenge


async def delete_challenge(
    db: AsyncSession, challenge: Challenge, cache: Redis | None = None
) -> None:
    has_solve = await db.scalar(select(Solve.id).where(Solve.challenge_id == challenge.id).limit(1))
    has_submission = await db.scalar(
        select(Submission.id).where(Submission.challenge_id == challenge.id).limit(1)
    )
    if has_solve is not None or has_submission is not None:
        raise HTTPException(status_code=409, detail="Cannot delete a challenge with submission or solve history")
    if challenge.seed_key is not None:
        db.add(DeletedChallengeSeed(seed_key=challenge.seed_key))
    await db.delete(challenge)
    await db.commit()
    await invalidate_challenges_cache(cache)
    await invalidate_scoreboard_cache(cache)
    if challenge.seed_key in {
        "web-01",
        "web-03-sqli",
        "web-04-path-traversal",
        "business-01",
        "reverse-01",
        "pwn-01",
    }:
        from app.platform.services.task_materials import refresh_lab_flags

        await refresh_lab_flags(db)


def public_challenge(challenge: Challenge, solved: bool = False) -> dict:
    return {
        "id": challenge.id,
        "title": challenge.title,
        "category": challenge.category,
        "description": challenge.description,
        "points": challenge.points,
        "resource_url": challenge.resource_url,
        "is_solved": solved,
    }


async def get_published_challenges(
    db: AsyncSession, cache: Redis | None = None
) -> list[dict]:
    cache_read = await get_json_cache(cache, CHALLENGES_CACHE_KEY, list)
    cached = cache_read.value
    if cached is not None:
        if isinstance(cached, list) and all(
            isinstance(challenge, dict)
            and isinstance(challenge.get("id"), int)
            and isinstance(challenge.get("title"), str)
            and isinstance(challenge.get("category"), str)
            and isinstance(challenge.get("description"), str)
            and isinstance(challenge.get("points"), int)
            and (
                challenge.get("resource_url") is None
                or isinstance(challenge.get("resource_url"), str)
            )
            for challenge in cached
        ):
            return cached
        await delete_cache_keys(cache, CHALLENGES_CACHE_KEY)
    challenges = (
        await db.scalars(
            select(Challenge)
            .where(Challenge.is_published.is_(True))
            .order_by(Challenge.id)
        )
    ).all()
    result = [public_challenge(challenge) for challenge in challenges]
    for challenge in result:
        challenge.pop("is_solved")
    await set_json_cache(cache, CHALLENGES_CACHE_KEY, result, cache_read.generation)
    return result


async def submit_flag(
    db: AsyncSession, user: User, challenge_id: int, flag: str, cache: Redis | None = None
) -> dict:
    try:
        flag = validate_flag_value(flag)
    except ValueError:
        raise HTTPException(status_code=422, detail="Flag must be between 1 and 256 characters")
    locked_user = await db.scalar(select(User).where(User.id == user.id).with_for_update())
    if locked_user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    now = datetime.now(timezone.utc)
    recent_count = await db.scalar(
        select(func.count(Submission.id)).where(
            Submission.user_id == user.id,
            Submission.submitted_at >= now - timedelta(minutes=1),
        )
    )
    if (recent_count or 0) >= 10:
        raise HTTPException(status_code=429, detail="Too many submissions. Try again in a minute.")
    challenge = await db.scalar(
        select(Challenge).where(Challenge.id == challenge_id, Challenge.is_published.is_(True))
    )
    if challenge is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    solved_before = await db.scalar(
        select(Solve.id).where(Solve.user_id == user.id, Solve.challenge_id == challenge.id)
    )
    correct = verify_flag(flag, challenge.flag_hash)
    db.add(Submission(user_id=user.id, challenge_id=challenge.id, is_correct=correct, submitted_at=now))
    if not correct:
        result = {"status": "incorrect", "is_correct": False}
    elif solved_before is not None:
        result = {"status": "already_solved", "is_correct": True, "awarded": False}
    else:
        db.add(Solve(user_id=user.id, challenge_id=challenge.id, solved_at=now))
        result = {"status": "correct", "is_correct": True, "awarded": True, "points": challenge.points}
    await db.commit()
    FLAG_SUBMISSIONS.labels(result=result["status"]).inc()
    if result["status"] == "correct":
        SOLVES_AWARDED.inc()
        await invalidate_scoreboard_cache(cache)
    return result


def set_flag(challenge: Challenge, flag: str) -> None:
    challenge.flag_hash = hash_flag(flag)
