import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.platform.core.security import encrypt_flag, hash_flag, hash_password
from app.platform.models import Challenge, DeletedChallengeSeed, User
from app.platform.schemas import ChallengeInput
from app.platform.services.challenges import create_challenge

logger = logging.getLogger(__name__)


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
    {
        "seed_key": "web-03-sqli",
        "title": "WEB-03 — Архив сотрудников",
        "category": "Web",
        "description": "В учебном каталоге сотрудников найдите способ обойти фильтр поиска и получить запись, не отображаемую при обычном поиске. Флаг хранится только в синтетической локальной базе лаборатории.",
        "points": 200,
        "flag": "CTF{union_of_synthetic_records}",
        "resource_url": "/lab/sql/",
    },
    {
        "seed_key": "web-04-path-traversal",
        "title": "WEB-04 — За пределами папки",
        "category": "Web",
        "description": "Файловый просмотрщик предназначен для публичной папки. Исследуйте обработку пути и найдите виртуальный закрытый файл с флагом. Лаборатория не читает настоящие файлы контейнера.",
        "points": 200,
        "flag": "CTF{virtual_paths_only}",
        "resource_url": "/lab/files/",
    },
    {
        "seed_key": "business-01",
        "title": "BIZ-01 — Магазин с ошибкой",
        "category": "Business Logic",
        "description": "В учебном магазине есть товар дороже баланса пользователя. Найдите ошибку проверки бизнес-логики, которая позволяет оформить заказ и получить флаг. Все цены и баланс вымышленные и сбрасываются при каждом запросе.",
        "points": 200,
        "flag": "CTF{negative_quantity_credit}",
        "resource_url": "/lab/shop/",
    },
)


async def ensure_admin(session: AsyncSession, username: str, password: str) -> None:
    existing = await session.scalar(select(User).where(User.username == username))
    if existing is None:
        session.add(
            User(
                username=username,
                password_hash=hash_password(password),
                is_admin=True,
                must_change_password=True,
            )
        )
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
        elif existing.flag_encrypted is None:
            logger.warning(
                "Challenge %s had no recoverable plaintext flag; restoring its bundled answer. "
                "Reapply any custom flag after this upgrade.",
                values["seed_key"],
            )
            existing.flag_hash = hash_flag(values["flag"])
            existing.flag_encrypted = encrypt_flag(values["flag"])
            await session.commit()
