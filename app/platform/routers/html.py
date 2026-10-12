from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import ValidationError

from app.platform.core.config import get_settings
from app.platform.core.security import hash_session_token, new_csrf_token
from app.platform.dependencies import admin_user, current_user, optional_user, require_csrf, session_context
from app.platform.models import AuthSession, Challenge, Solve, Submission, User
from app.platform.routers.auth import user_view
from app.platform.schemas import ChallengeInput, ChallengePatch, Credentials
from app.platform.services.auth import UsernameUnavailable, authenticate_user, register_user
from app.platform.services.challenges import (
    create_challenge as create_challenge_record,
    delete_challenge as delete_challenge_record,
    public_challenge,
    submit_flag,
    update_challenge as update_challenge_record,
    validate_resource_url,
)
from app.platform.services.scoreboard import get_scoreboard
from app.platform.services.sessions import create_session, delete_session
from app.platform.storage import get_db

router = APIRouter()
templates = Jinja2Templates(directory=str(get_settings().templates_dir))


async def render(
    request: Request,
    name: str,
    context: dict | None = None,
    status_code: int = 200,
    db: AsyncSession | None = None,
) -> Response:
    values = context or {}
    user: User | None = None
    auth_session: AuthSession | None = None
    if db is not None:
        user, auth_session = await session_context(request, db)
        if auth_session is not None and auth_session.flash_message:
            values["flash"] = {"message": auth_session.flash_message, "kind": auth_session.flash_kind or "success"}
            auth_session.flash_message = None
            auth_session.flash_kind = None
            await db.commit()
    csrf = request.cookies.get("cyberarena_csrf") or new_csrf_token()
    response = templates.TemplateResponse(
        request=request,
        name=name,
        context={"request": request, "user": user, "csrf_token": csrf, **values},
        status_code=status_code,
    )
    if request.cookies.get("cyberarena_csrf") is None:
        response.set_cookie(
            "cyberarena_csrf",
            csrf,
            httponly=False,
            secure=get_settings().secure_cookies,
            samesite="lax",
            max_age=86400,
            path="/",
        )
    return response


async def form_values(request: Request) -> dict[str, str]:
    form = await request.form()
    return {key: str(value) for key, value in form.items()}


def set_flash(auth_session: AuthSession, message: str, kind: str = "success") -> None:
    auth_session.flash_message = message
    auth_session.flash_kind = kind


@router.get("/")
async def home() -> RedirectResponse:
    return RedirectResponse("/challenges", status_code=303)


@router.get("/tasks/crypto01/download", include_in_schema=False)
async def crypto_download() -> FileResponse:
    path = get_settings().static_dir / "tasks" / "crypto01" / "ciphertext.txt"
    return FileResponse(path, media_type="text/plain; charset=utf-8", filename="crypto01-ciphertext.txt")


@router.get("/login")
async def login_page(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    return await render(request, "auth/login.html", db=db)


@router.post("/login", dependencies=[Depends(require_csrf)])
async def login_form(request: Request, response: Response, db: AsyncSession = Depends(get_db)) -> Response:
    values = await form_values(request)
    try:
        credentials = Credentials.model_validate(values)
    except ValidationError:
        return await render(request, "auth/login.html", {"error": "Проверьте логин и пароль."}, 422, db)
    user = await authenticate_user(db, credentials)
    if user is None:
        return await render(request, "auth/login.html", {"error": "Неверный логин или пароль."}, 401, db)
    response = RedirectResponse("/challenges", status_code=303)
    auth_session = await create_session(db, response, user, request.cookies.get("cyberarena_csrf"))
    set_flash(auth_session, "Вы вошли в аккаунт.")
    await db.commit()
    return response


@router.get("/register")
async def register_page(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    return await render(request, "auth/register.html", db=db)


@router.post("/register", dependencies=[Depends(require_csrf)])
async def register_form(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    values = await form_values(request)
    try:
        credentials = Credentials.model_validate(values)
    except ValidationError:
        return await render(request, "auth/register.html", {"error": "Логин должен содержать 3–32 латинских буквы, цифры или подчёркивания; пароль — не менее 10 символов."}, 422, db)
    try:
        user = await register_user(db, credentials)
    except UsernameUnavailable:
        return await render(request, "auth/register.html", {"error": "Этот логин уже занят."}, 409, db)
    response = RedirectResponse("/challenges", status_code=303)
    auth_session = await create_session(db, response, user, request.cookies.get("cyberarena_csrf"))
    set_flash(auth_session, "Аккаунт создан. Добро пожаловать в CYBERARENA.")
    await db.commit()
    return response


@router.post("/logout", dependencies=[Depends(require_csrf)])
async def logout_form(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    response = RedirectResponse("/login", status_code=303)
    await delete_session(db, request, response)
    return response


@router.get("/logout")
async def logout_get() -> Response:
    return Response(status_code=405, headers={"Allow": "POST"})


@router.get("/challenges")
async def challenge_list(
    request: Request,
    user: User | None = Depends(optional_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    values = (await db.scalars(select(Challenge).where(Challenge.is_published.is_(True)).order_by(Challenge.id))).all()
    solved = set()
    if user:
        solved = set((await db.scalars(select(Solve.challenge_id).where(Solve.user_id == user.id))).all())
    return await render(request, "challenges/list.html", {"challenges": [public_challenge(c, c.id in solved) for c in values]}, db=db)


@router.get("/challenges/{challenge_id}")
async def challenge_page(
    challenge_id: int,
    request: Request,
    user: User | None = Depends(optional_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    challenge = await db.scalar(select(Challenge).where(Challenge.id == challenge_id, Challenge.is_published.is_(True)))
    if challenge is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    solved = bool(user and await db.scalar(select(Solve.id).where(Solve.user_id == user.id, Solve.challenge_id == challenge.id)))
    return await render(request, "challenges/detail.html", {"challenge": public_challenge(challenge, solved)}, db=db)


@router.post("/challenges/{challenge_id}/submit", dependencies=[Depends(require_csrf)])
async def challenge_submit_form(
    challenge_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    form = await form_values(request)
    result = await submit_flag(db, user, challenge_id, form.get("flag", ""))
    message = {
        "incorrect": ("Неверный флаг.", "error"),
        "already_solved": ("Вы уже решили это задание.", "info"),
        "correct": (f"Верный флаг! Начислено баллов: {result.get('points', 0)}.", "success"),
    }[result["status"]]
    auth_session = await db.get(AuthSession, hash_session_token(request.cookies["cyberarena_session"]))
    if auth_session:
        set_flash(auth_session, *message)
        await db.commit()
    return RedirectResponse(f"/challenges/{challenge_id}", status_code=303)


@router.get("/scoreboard")
async def scoreboard_page(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    return await render(request, "scoreboard.html", {"rows": await get_scoreboard(db)}, db=db)


@router.get("/profile")
async def profile_page(
    request: Request,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    solves = (
        await db.execute(
            select(Solve, Challenge)
            .join(Challenge, Challenge.id == Solve.challenge_id)
            .where(Solve.user_id == user.id)
            .order_by(Solve.solved_at.desc())
        )
    ).all()
    return await render(request, "profile.html", {"profile": user_view(user), "solves": solves}, db=db)


@router.get("/admin")
async def admin_dashboard(request: Request, _: User = Depends(admin_user), db: AsyncSession = Depends(get_db)) -> Response:
    from sqlalchemy import func
    counts = {
        "challenges": await db.scalar(select(func.count(Challenge.id))),
        "submissions": await db.scalar(select(func.count(Submission.id))),
        "solves": await db.scalar(select(func.count(Solve.id))),
    }
    return await render(request, "admin/dashboard.html", {"counts": counts}, db=db)


@router.get("/admin/challenges")
async def admin_challenge_list(request: Request, _: User = Depends(admin_user), db: AsyncSession = Depends(get_db)) -> Response:
    values = (await db.scalars(select(Challenge).order_by(Challenge.id.desc()))).all()
    return await render(request, "admin/challenges/list.html", {"challenges": values}, db=db)


@router.get("/admin/challenges/new")
async def admin_challenge_new(request: Request, _: User = Depends(admin_user), db: AsyncSession = Depends(get_db)) -> Response:
    return await render(request, "admin/challenges/form.html", {"challenge": None}, db=db)


@router.get("/admin/challenges/{challenge_id}/edit")
async def admin_challenge_edit(challenge_id: int, request: Request, _: User = Depends(admin_user), db: AsyncSession = Depends(get_db)) -> Response:
    challenge = await db.get(Challenge, challenge_id)
    if challenge is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    return await render(request, "admin/challenges/form.html", {"challenge": challenge}, db=db)


@router.post("/admin/challenges", dependencies=[Depends(require_csrf)])
async def admin_challenge_create_form(request: Request, _: User = Depends(admin_user), db: AsyncSession = Depends(get_db)) -> Response:
    form = await form_values(request)
    try:
        data = ChallengeInput.model_validate({**form, "is_published": form.get("is_published") == "on", "resource_url": form.get("resource_url") or None})
        validate_resource_url(data.resource_url)
    except (ValidationError, HTTPException):
        return await render(request, "admin/challenges/form.html", {"error": "Проверьте поля задания."}, 422, db)
    await create_challenge_record(db, data)
    return RedirectResponse("/admin/challenges", status_code=303)


@router.post("/admin/challenges/{challenge_id}/edit", dependencies=[Depends(require_csrf)])
async def admin_challenge_update_form(challenge_id: int, request: Request, _: User = Depends(admin_user), db: AsyncSession = Depends(get_db)) -> Response:
    challenge = await db.get(Challenge, challenge_id)
    if challenge is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    form = await form_values(request)
    try:
        candidate = ChallengeInput.model_validate({
            "title": form.get("title"), "category": form.get("category"),
            "description": form.get("description"), "points": form.get("points"),
            "flag": form.get("flag") or "unchanged-placeholder",
            "is_published": form.get("is_published") == "on",
            "resource_url": form.get("resource_url") or None,
        })
        data = ChallengePatch(
            title=candidate.title, category=candidate.category, description=candidate.description,
            points=candidate.points, flag=form.get("flag") or None,
            is_published=candidate.is_published, resource_url=candidate.resource_url,
        )
        validate_resource_url(data.resource_url)
    except (ValidationError, HTTPException):
        return await render(request, "admin/challenges/form.html", {"error": "Проверьте поля задания.", "challenge": challenge}, 422, db)
    await update_challenge_record(db, challenge, data)
    return RedirectResponse("/admin/challenges", status_code=303)


@router.post("/admin/challenges/{challenge_id}/publish", dependencies=[Depends(require_csrf)])
async def admin_publish_form(challenge_id: int, _: User = Depends(admin_user), db: AsyncSession = Depends(get_db)) -> Response:
    challenge = await db.get(Challenge, challenge_id)
    if challenge is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    challenge.is_published = True
    await db.commit()
    return RedirectResponse("/admin/challenges", status_code=303)


@router.post("/admin/challenges/{challenge_id}/unpublish", dependencies=[Depends(require_csrf)])
async def admin_unpublish_form(challenge_id: int, _: User = Depends(admin_user), db: AsyncSession = Depends(get_db)) -> Response:
    challenge = await db.get(Challenge, challenge_id)
    if challenge is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    challenge.is_published = False
    await db.commit()
    return RedirectResponse("/admin/challenges", status_code=303)


@router.post("/admin/challenges/{challenge_id}/delete", dependencies=[Depends(require_csrf)])
async def admin_delete_form(challenge_id: int, request: Request, _: User = Depends(admin_user), db: AsyncSession = Depends(get_db)) -> Response:
    challenge = await db.get(Challenge, challenge_id)
    if challenge is None:
        raise HTTPException(status_code=404, detail="Challenge not found")
    try:
        await delete_challenge_record(db, challenge)
    except HTTPException as exc:
        if exc.status_code != 409:
            raise
        return await render(request, "admin/challenges/list.html", {"error": "Нельзя удалить задание: у него есть история попыток или решений.", "challenges": (await db.scalars(select(Challenge))).all()}, 409, db)
    return RedirectResponse("/admin/challenges", status_code=303)


@router.get("/admin/submissions")
async def admin_submissions(request: Request, _: User = Depends(admin_user), db: AsyncSession = Depends(get_db)) -> Response:
    rows = (
        await db.execute(select(Submission, User.username, Challenge.title).join(User).join(Challenge).order_by(Submission.submitted_at.desc()).limit(500))
    ).all()
    return await render(request, "admin/submissions.html", {"rows": rows}, db=db)


@router.get("/admin/solves")
async def admin_solves(request: Request, _: User = Depends(admin_user), db: AsyncSession = Depends(get_db)) -> Response:
    rows = (
        await db.execute(select(Solve, User.username, Challenge.title, Challenge.points).join(User).join(Challenge).order_by(Solve.solved_at.desc()).limit(500))
    ).all()
    return await render(request, "admin/solves.html", {"rows": rows}, db=db)


@router.get("/admin/scoreboard")
async def admin_scoreboard_page(request: Request, _: User = Depends(admin_user), db: AsyncSession = Depends(get_db)) -> Response:
    return await render(request, "admin/scoreboard.html", {"rows": await get_scoreboard(db)}, db=db)


@router.post("/admin/tournament/reset", dependencies=[Depends(require_csrf)])
async def admin_reset_form(request: Request, _: User = Depends(admin_user), db: AsyncSession = Depends(get_db)) -> Response:
    await db.execute(Submission.__table__.delete())
    await db.execute(Solve.__table__.delete())
    await db.commit()
    auth_session = await db.get(AuthSession, hash_session_token(request.cookies["cyberarena_session"]))
    if auth_session:
        set_flash(auth_session, "Результаты турнира сброшены.", "success")
        await db.commit()
    return RedirectResponse("/admin", status_code=303)
