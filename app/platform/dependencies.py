import secrets
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.platform.models import AuthSession, User
from app.platform.storage import get_db
from app.platform.core.security import hash_session_token


async def session_context(
    request: Request, db: AsyncSession = Depends(get_db)
) -> tuple[User | None, AuthSession | None]:
    token = request.cookies.get("cyberarena_session")
    if not token:
        return None, None
    auth_session = await db.get(AuthSession, hash_session_token(token))
    expires_at = auth_session.expires_at if auth_session is not None else None
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if auth_session is None or expires_at <= datetime.now(timezone.utc):
        if auth_session is not None:
            await db.delete(auth_session)
            await db.commit()
        return None, None
    user = await db.get(User, auth_session.user_id)
    return user, auth_session


async def current_user(
    context: tuple[User | None, AuthSession | None] = Depends(session_context),
) -> User:
    user, _ = context
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return user


async def optional_user(
    context: tuple[User | None, AuthSession | None] = Depends(session_context),
) -> User | None:
    return context[0]


async def admin_user(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator access required")
    return user


async def require_csrf(request: Request, db: AsyncSession = Depends(get_db)) -> None:
    cookie = request.cookies.get("cyberarena_csrf")
    supplied = request.headers.get("x-csrf-token")
    if supplied is None and request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
        form = await request.form()
        supplied = str(form.get("csrf_token", ""))
    if not cookie or not supplied or not secrets.compare_digest(cookie, supplied):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    context = await session_context(request, db)
    if context[1] is not None and not secrets.compare_digest(context[1].csrf_token, cookie):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
