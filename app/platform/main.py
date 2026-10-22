from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.http_errors import register_error_handlers
from app.platform.core.config import get_settings
from app.platform.dependencies import admin_user
from app.platform.routers import admin, auth, challenges, html, scoreboard
from app.platform.services.bootstrap import ensure_admin, seed_challenges
from app.platform.services.task_materials import refresh_lab_flags
from app.platform.storage import close_database, get_db, get_session_factory


@asynccontextmanager
async def lifespan(fastapi_app: FastAPI):
    settings = get_settings()
    if not settings.admin_username or not settings.admin_password:
        raise RuntimeError("ADMIN_USERNAME and ADMIN_PASSWORD must be configured")
    cache = Redis.from_url(settings.redis_url, decode_responses=True) if settings.redis_url else None
    fastapi_app.state.redis = cache
    try:
        async with get_session_factory()() as session:
            await ensure_admin(session, settings.admin_username, settings.admin_password)
            await seed_challenges(session)
            await refresh_lab_flags(session)
        yield
    finally:
        if cache is not None:
            await cache.aclose()
        await close_database()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="CYBERARENA",
        version="1.0.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    register_error_handlers(app)
    app.include_router(auth.router)
    app.include_router(challenges.router)
    app.include_router(scoreboard.router)
    app.include_router(admin.router)
    app.include_router(html.router)
    app.mount("/static", StaticFiles(directory=settings.static_dir), name="static")

    @app.get("/openapi.json", include_in_schema=False, dependencies=[Depends(admin_user)])
    async def openapi_schema() -> JSONResponse:
        return JSONResponse(app.openapi())

    @app.get("/docs", include_in_schema=False, dependencies=[Depends(admin_user)])
    async def swagger_docs() -> HTMLResponse:
        return get_swagger_ui_html(
            openapi_url="/openapi.json",
            title=f"{app.title} - Swagger UI",
        )


    @app.get("/health", include_in_schema=False)
    async def health(db: AsyncSession = Depends(get_db)) -> dict[str, str]:
        await db.execute(text("SELECT 1"))
        return {"status": "ok"}

    return app


app = create_app()
