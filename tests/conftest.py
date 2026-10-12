import asyncio
import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine

EXTERNAL_TEST_DATABASE_URL = os.getenv("CYBERARENA_TEST_DATABASE_URL")
if EXTERNAL_TEST_DATABASE_URL:
    database_name = EXTERNAL_TEST_DATABASE_URL.split("?", 1)[0].rsplit("/", 1)[-1]
    if not EXTERNAL_TEST_DATABASE_URL.startswith("postgresql+asyncpg://") or not database_name.startswith("cyberarena_test"):
        raise RuntimeError("CYBERARENA_TEST_DATABASE_URL must be a dedicated PostgreSQL database named cyberarena_test*")
    os.environ["DATABASE_URL"] = EXTERNAL_TEST_DATABASE_URL
    TEST_DATABASE_URL = EXTERNAL_TEST_DATABASE_URL
else:
    TEST_DB_DIRECTORY = tempfile.TemporaryDirectory(prefix="cyberarena-tests-")
    TEST_DB = str(Path(TEST_DB_DIRECTORY.name) / "platform.sqlite")
    TEST_DATABASE_URL = f"sqlite+aiosqlite:///{TEST_DB}"
    os.environ.setdefault("DATABASE_URL", TEST_DATABASE_URL)
os.environ.setdefault("SECRET_KEY", "test-secret-key-that-is-at-least-32-characters-long")
os.environ.setdefault("FLAG_HMAC_KEY", "test-flag-hmac-key-that-is-at-least-32-characters-long")
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "testing-admin-password-strong")
os.environ.setdefault("COOKIE_SECURE", "false")

from app.platform.main import app
from app.platform.models import Base

@pytest.fixture
def client():
    async def reset_database():
        engine = create_async_engine(TEST_DATABASE_URL)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.drop_all)
            await connection.run_sync(Base.metadata.create_all)
        await engine.dispose()

    asyncio.run(reset_database())
    with TestClient(app) as test_client:
        yield test_client


def csrf(client: TestClient) -> str:
    return client.get("/api/auth/csrf").json()["csrf_token"]


def register(client: TestClient, username: str = "player1", password: str = "user-password-123") -> None:
    token = csrf(client)
    response = client.post(
        "/api/auth/register",
        json={"username": username, "password": password},
        headers={"X-CSRF-Token": token},
    )
    assert response.status_code == 201


def admin_client(client: TestClient) -> TestClient:
    token = csrf(client)
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": os.environ["ADMIN_PASSWORD"]},
        headers={"X-CSRF-Token": token},
    )
    assert response.status_code == 200
    return client


def create_challenge(client: TestClient, flag: str, points: int = 100, published: bool = True) -> int:
    token = csrf(client)
    response = client.post(
        "/api/admin/challenges",
        json={
            "title": f"Challenge {flag[-3:]}",
            "category": "Web",
            "description": "Find the flag.",
            "points": points,
            "flag": flag,
            "is_published": published,
            "resource_url": "/lab/",
        },
        headers={"X-CSRF-Token": token},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]
