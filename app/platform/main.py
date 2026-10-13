from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.platform.core.config import get_settings
from app.platform.routers import admin, auth, challenges, html, scoreboard
from app.platform.services.bootstrap import ensure_admin, seed_challenges
from app.platform.services.task_materials import refresh_lab_flags
from app.platform.storage import close_database, get_db, get_session_factory


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    if not settings.admin_username or not settings.admin_password:
        raise RuntimeError("ADMIN_USERNAME and ADMIN_PASSWORD must be configured")
    async with get_session_factory()() as session:
        await ensure_admin(session, settings.admin_username, settings.admin_password)
        await seed_challenges(session)
        await refresh_lab_flags(session)
    yield
    await close_database()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="CYBERARENA", version="1.0.0", lifespan=lifespan)
    app.include_router(auth.router)
    app.include_router(challenges.router)
    app.include_router(scoreboard.router)
    app.include_router(admin.router)
    app.include_router(html.router)
    app.mount("/static", StaticFiles(directory=settings.static_dir), name="static")


    @app.get("/health", include_in_schema=False)
    async def health(db: AsyncSession = Depends(get_db)) -> dict[str, str]:
        await db.execute(text("SELECT 1"))
        return {"status": "ok"}

    return app


app = create_app()
