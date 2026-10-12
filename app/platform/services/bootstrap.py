from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.platform.core.security import hash_password
from app.platform.models import Challenge, DeletedChallengeSeed, User
from app.platform.schemas import ChallengeInput
from app.platform.services.challenges import create_challenge


SEED_CHALLENGES = (
    {
        "seed_key": "web-01",
        "title": "WEB-01 — Скрытый документ",
        "category": "Web",
        "description": "В учебном веб-приложении есть карточки документов. Изучите их идентификаторы и найдите доступ к закрытой тестовой странице другого пользователя. Используйте только лабораторию; флаг находится в документе с ID 1002.",
        "points": 100,
        "flag": "CTF{idor_hidden_document}",
        "resource_url": "/lab/",
    },
    {
        "seed_key": "web-02",
        "title": "WEB-02 — Посмотри исходник",
        "category": "Web",
        "description": "Страница выглядит пустой, но автор оставил подсказку в клиентском коде. Исследуйте HTML и подключённый локальный JavaScript, чтобы найти флаг.",
        "points": 150,
        "flag": "CTF{source_maps_are_not_needed}",
        "resource_url": "/static/tasks/web02/index.html",
    },
    {
        "seed_key": "crypto-01",
        "title": "CRYPTO-01 — Три шага назад",
        "category": "Crypto",
        "description": "В приложенном файле флаг зашифрован шифром Цезаря со сдвигом на 3 символа вперёд. Верните каждую латинскую букву на три позиции назад; регистр, фигурные скобки и подчёркивания сохранены.",
        "points": 150,
        "flag": "CTF{caesar_shift_is_fun}",
        "resource_url": "/tasks/crypto01/download",
    },
)


async def ensure_admin(session: AsyncSession, username: str, password: str) -> None:
    existing = await session.scalar(select(User).where(User.username == username))
    if existing is None:
        session.add(User(username=username, password_hash=hash_password(password), is_admin=True))
        await session.commit()
    elif not existing.is_admin:
        raise RuntimeError("ADMIN_USERNAME is already assigned to a non-admin account")


async def seed_challenges(session: AsyncSession) -> None:
    for values in SEED_CHALLENGES:
        deleted = await session.get(DeletedChallengeSeed, values["seed_key"])
        if deleted is not None:
            continue
        existing = await session.scalar(
            select(Challenge).where(Challenge.seed_key == values["seed_key"])
        )
        if existing is None:
            challenge = await create_challenge(
                session,
                ChallengeInput(
                    title=values["title"],
                    category=values["category"],
                    description=values["description"],
                    points=values["points"],
                    flag=values["flag"],
                    is_published=True,
                    resource_url=values["resource_url"],
                ),
            )
            challenge.seed_key = values["seed_key"]
            await session.commit()
