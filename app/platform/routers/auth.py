from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.platform.core.config import get_settings
from app.platform.core.security import new_csrf_token
from app.platform.dependencies import current_user, password_change_admin, require_csrf
from app.platform.metrics import REGISTRATIONS
from app.platform.models import AuthSession, User
from app.platform.schemas import AdminPasswordChange, Credentials
from app.platform.services.auth import UsernameUnavailable, authenticate_user, change_admin_password, register_user
from app.platform.services.sessions import create_session, delete_session
from app.platform.storage import get_db

router = APIRouter()


def user_view(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "is_admin": user.is_admin,
        "must_change_password": user.must_change_password,
        "created_at": user.created_at,
    }


@router.get("/api/auth/csrf")
async def csrf_token(request: Request, response: Response) -> dict[str, str]:
    cookie = request.cookies.get("cyberarena_csrf") or new_csrf_token()
    response.set_cookie(
        "cyberarena_csrf",
        cookie,
        httponly=False,
        secure=get_settings().secure_cookies,
        samesite="lax",
        max_age=86400,
        path="/",
    )
    return {"csrf_token": cookie}


@router.post("/api/auth/register", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_csrf)])
async def register(
    credentials: Credentials,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> dict:
    try:
        user = await register_user(db, credentials)
    except UsernameUnavailable:
        raise HTTPException(status_code=409, detail="Username is unavailable") from None
    REGISTRATIONS.inc()
    await create_session(db, response, user, request.cookies.get("cyberarena_csrf"))
    return {"user": user_view(user)}


@router.post("/api/auth/login", dependencies=[Depends(require_csrf)])
async def login(
    credentials: Credentials,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> dict:
    user = await authenticate_user(db, credentials)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    await create_session(db, response, user, request.cookies.get("cyberarena_csrf"))
    return {"user": user_view(user)}


@router.post("/api/auth/logout", dependencies=[Depends(require_csrf)])
async def logout(request: Request, response: Response, db: AsyncSession = Depends(get_db)) -> dict:
    await delete_session(db, request, response)
    return {"status": "logged_out"}


@router.post("/api/auth/admin/change-password", dependencies=[Depends(require_csrf)])
async def change_admin_password_api(
    data: AdminPasswordChange,
    context: tuple[User, AuthSession] = Depends(password_change_admin),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    user, auth_session = context
    try:
        await change_admin_password(
            db, user, auth_session, data.current_password, data.new_password
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return {"status": "password_changed"}


@router.get("/api/users/me")
async def me(user: User = Depends(current_user)) -> dict:
    return user_view(user)
