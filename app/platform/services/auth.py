from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.platform.core.security import hash_password, verify_password
from app.platform.models import User
from app.platform.schemas import Credentials


class UsernameUnavailable(Exception):
    pass


async def register_user(db: AsyncSession, credentials: Credentials) -> User:
    user = User(username=credentials.username, password_hash=hash_password(credentials.password))
    db.add(user)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise UsernameUnavailable from None
    await db.refresh(user)
    return user


async def authenticate_user(db: AsyncSession, credentials: Credentials) -> User | None:
    user = await db.scalar(select(User).where(User.username == credentials.username))
    if user is None or not verify_password(credentials.password, user.password_hash):
        return None
    return user
