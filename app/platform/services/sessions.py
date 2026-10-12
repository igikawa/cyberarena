from datetime import datetime, timedelta, timezone

from fastapi import Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.platform.core.config import get_settings
from app.platform.core.security import hash_session_token, new_csrf_token, new_session_token
from app.platform.models import AuthSession, User

SESSION_COOKIE = "cyberarena_session"
CSRF_COOKIE = "cyberarena_csrf"


async def create_session(db: AsyncSession, response: Response, user: User, csrf: str | None = None) -> AuthSession:
    settings = get_settings()
    token = new_session_token()
    csrf = csrf or new_csrf_token()
    auth_session = AuthSession(
        token_hash=hash_session_token(token),
        csrf_token=csrf,
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=settings.session_ttl_hours),
    )
    db.add(auth_session)
    await db.commit()
    response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=settings.secure_cookies, samesite="lax", max_age=settings.session_ttl_hours * 3600, path="/")
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=settings.secure_cookies, samesite="lax", max_age=settings.session_ttl_hours * 3600, path="/")
    return auth_session


async def delete_session(db: AsyncSession, request: Request, response: Response) -> None:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        auth_session = await db.get(AuthSession, hash_session_token(token))
        if auth_session is not None:
            await db.delete(auth_session)
            await db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")
