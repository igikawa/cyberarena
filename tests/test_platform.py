import os
import asyncio
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.lab.main import app as lab_app
from app.platform.models import DeletedChallengeSeed
from app.platform.services.scoreboard import get_scoreboard
from tests.conftest import TEST_DATABASE_URL, admin_client, create_challenge, csrf, register


def test_registration_and_duplicate_username(client: TestClient):
    token = csrf(client)
    payload = {"username": "alice", "password": "long-password-123"}
    assert client.post("/api/auth/register", json=payload, headers={"X-CSRF-Token": token}).status_code == 201
    response = client.post("/api/auth/register", json=payload, headers={"X-CSRF-Token": token})
    assert response.status_code == 409


def test_login_success_and_failure(client: TestClient):
    register(client, "loginuser")
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    token = csrf(client)
    assert client.post(
        "/api/auth/login",
        json={"username": "loginuser", "password": "user-password-123"},
        headers={"X-CSRF-Token": token},
    ).status_code == 200
    response = client.post(
        "/api/auth/login",
        json={"username": "loginuser", "password": "wrong-password"},
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert response.status_code == 401


def test_admin_api_denies_regular_user(client: TestClient):
    register(client)
    response = client.get("/api/admin/challenges")
    assert response.status_code == 403


def test_admin_can_create_challenge(client: TestClient):
    admin_client(client)
    challenge_id = create_challenge(client, "flag{admin-create}")
    assert client.get(f"/api/admin/challenges/{challenge_id}").status_code == 200


def test_challenge_validation_rejects_blank_and_null_required_fields(client: TestClient):
    admin_client(client)
    token = csrf(client)
    blank = client.post(
        "/api/admin/challenges",
        json={
            "title": "   ",
            "category": "Web",
            "description": "description",
            "points": 100,
            "flag": "CTF{validation}",
        },
        headers={"X-CSRF-Token": token},
    )
    assert blank.status_code == 422
    challenge_id = create_challenge(client, "flag{nonnull}")
    null_points = client.patch(
        f"/api/admin/challenges/{challenge_id}",
        json={"points": None},
        headers={"X-CSRF-Token": token},
    )
    assert null_points.status_code == 422
    whitespace_title = client.patch(
        f"/api/admin/challenges/{challenge_id}",
        json={"title": "  "},
        headers={"X-CSRF-Token": token},
    )
    assert whitespace_title.status_code == 422


def test_deleting_seeded_challenge_records_tombstone(client: TestClient):
    admin_client(client)
    challenge = next(
        row for row in client.get("/api/admin/challenges").json()
        if row["title"].startswith("WEB-02")
    )
    assert client.delete(
        f"/api/admin/challenges/{challenge['id']}",
        headers={"X-CSRF-Token": csrf(client)},
    ).status_code == 204

    async def tombstone_exists():
        engine = create_async_engine(TEST_DATABASE_URL)
        try:
            async with async_sessionmaker(engine)() as session:
                return await session.get(DeletedChallengeSeed, "web-02")
        finally:
            await engine.dispose()

    assert asyncio.run(tombstone_exists()) is not None


def test_public_challenge_does_not_expose_flag(client: TestClient):
    admin_client(client)
    challenge_id = create_challenge(client, "flag{secret-value}")
    response = client.get(f"/api/challenges/{challenge_id}")
    assert response.status_code == 200
    assert "flag{secret-value}" not in response.text
    assert "flag_hash" not in response.text


def test_wrong_flag_is_rejected(client: TestClient):
    admin_client(client)
    challenge_id = create_challenge(client, "flag{right-value}")
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    register(client)
    response = client.post(
        f"/api/challenges/{challenge_id}/submit",
        json={"flag": "flag{wrong-value}"},
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "incorrect"
    assert client.get("/api/scoreboard").json()[0]["score"] == 0


def test_first_correct_flag_awards_points_once(client: TestClient):
    admin_client(client)
    challenge_id = create_challenge(client, "flag{one-time}")
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    register(client)
    token = csrf(client)
    payload = {"flag": "flag{one-time}"}
    first = client.post(f"/api/challenges/{challenge_id}/submit", json=payload, headers={"X-CSRF-Token": token})
    second = client.post(f"/api/challenges/{challenge_id}/submit", json=payload, headers={"X-CSRF-Token": token})
    assert first.json()["status"] == "correct"
    assert first.json()["awarded"] is True
    assert second.json()["status"] == "already_solved"
    assert second.json()["awarded"] is False
    assert client.get("/api/scoreboard").json()[0]["score"] == 100


def test_concurrent_correct_submissions_award_points_once(client: TestClient):
    if not TEST_DATABASE_URL.startswith("postgresql+asyncpg://"):
        import pytest
        pytest.skip("Concurrent locking is verified against the dedicated PostgreSQL integration database")
    admin_client(client)
    challenge_id = create_challenge(client, "flag{concurrent-once}", points=90)
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    register(client, "concurrent")
    session_token = client.cookies.get("cyberarena_session")
    csrf_token = csrf(client)

    def submit_once():
        return client.post(
            f"/api/challenges/{challenge_id}/submit",
            json={"flag": "flag{concurrent-once}"},
            headers={
                "X-CSRF-Token": csrf_token,
                "Cookie": f"cyberarena_session={session_token}; cyberarena_csrf={csrf_token}",
            },
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: submit_once(), range(8)))
    assert all(response.status_code == 200 for response in results)
    assert sum(response.json()["status"] == "correct" for response in results) == 1
    assert sum(response.json()["status"] == "already_solved" for response in results) == 7
    assert client.get("/api/scoreboard").json()[0]["score"] == 90


def test_scoreboard_sorts_by_score(client: TestClient):
    admin_client(client)
    first_challenge = create_challenge(client, "flag{low}", points=50)
    second_challenge = create_challenge(client, "flag{high}", points=200)
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    register(client, "lowplayer")
    token = csrf(client)
    client.post(f"/api/challenges/{first_challenge}/submit", json={"flag": "flag{low}"}, headers={"X-CSRF-Token": token})
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    register(client, "highplayer")
    token = csrf(client)
    client.post(f"/api/challenges/{second_challenge}/submit", json={"flag": "flag{high}"}, headers={"X-CSRF-Token": token})
    assert [row["username"] for row in client.get("/api/scoreboard").json()[:2]] == ["highplayer", "lowplayer"]


def test_unpublished_challenge_is_not_public(client: TestClient):
    admin_client(client)
    challenge_id = create_challenge(client, "flag{hidden}", published=False)
    assert client.get(f"/api/challenges/{challenge_id}").status_code == 404
    assert all(item["id"] != challenge_id for item in client.get("/api/challenges").json())


def test_html_forms_require_csrf(client: TestClient):
    assert client.get("/register").status_code == 200
    response = client.post("/register", data={"username": "csrfuser", "password": "password-is-long"})
    assert response.status_code == 403


def test_html_registration_issues_csrf_cookie_and_authenticates(client: TestClient):
    page = client.get("/register")
    assert page.status_code == 200
    token = client.cookies.get("cyberarena_csrf")
    assert token and token in page.text
    response = client.post(
        "/register",
        data={"username": "htmlplayer", "password": "a-long-password", "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    assert client.get("/profile").status_code == 200
    assert client.post(
        "/logout",
        data={"csrf_token": client.cookies.get("cyberarena_csrf")},
        follow_redirects=False,
    ).status_code == 303
    login_page = client.get("/login")
    login_csrf = client.cookies.get("cyberarena_csrf")
    assert login_csrf and login_csrf in login_page.text
    assert client.post(
        "/login",
        data={"username": "htmlplayer", "password": "a-long-password", "csrf_token": login_csrf},
        follow_redirects=False,
    ).status_code == 303
    assert client.get("/profile").status_code == 200


def test_admin_can_login_with_html_form(client: TestClient):
    page = client.get("/login")
    token = client.cookies.get("cyberarena_csrf")
    assert page.status_code == 200 and token and token in page.text
    response = client.post(
        "/login",
        data={"username": "admin", "password": os.environ["ADMIN_PASSWORD"], "csrf_token": token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert client.get("/admin").status_code == 200


def test_seeded_challenges_and_local_resources(client: TestClient):
    challenges = client.get("/api/challenges").json()
    assert [(item["category"], item["points"]) for item in challenges[:3]] == [
        ("Web", 100),
        ("Web", 150),
        ("Crypto", 150),
    ]
    assert all("flag" not in item and "flag_hash" not in item for item in challenges)
    web02 = client.get("/static/tasks/web02/index.html")
    script = client.get("/static/tasks/web02/clue.js")
    assert web02.status_code == script.status_code == 200
    assert "CTF{source_maps_are_not_needed}" in script.text
    crypto = client.get("/tasks/crypto01/download")
    assert crypto.status_code == 200
    assert "attachment" in crypto.headers["content-disposition"]
    assert "FWI{fdhvdu_vkliw_lv_ixq}" in crypto.text


def test_isolated_web_lab_idor_and_allowlisted_documents():
    with TestClient(lab_app) as lab:
        assert lab.get("/").status_code == 200
        assert lab.get("/documents/1001").status_code == 200
        exposed = lab.get("/documents/1002")
        assert exposed.status_code == 200
        assert "CTF{idor_hidden_document}" in exposed.text
        assert lab.get("/documents/1003").status_code == 404


def test_admin_html_lifecycle_and_tournament_reset(client: TestClient):
    admin_client(client)
    token = csrf(client)
    created = client.post(
        "/admin/challenges",
        data={
            "csrf_token": token,
            "title": "HTML admin challenge",
            "category": "Web",
            "description": "Admin form test",
            "points": "80",
            "flag": "CTF{html_admin_flag}",
            "is_published": "on",
            "resource_url": "/lab/",
        },
        follow_redirects=False,
    )
    assert created.status_code == 303, created.text
    challenge_id = client.get("/api/admin/challenges").json()[-1]["id"]
    assert client.get(f"/challenges/{challenge_id}").status_code == 200
    assert client.post(
        f"/admin/challenges/{challenge_id}/unpublish",
        data={"csrf_token": csrf(client)},
        follow_redirects=False,
    ).status_code == 303
    assert client.get(f"/challenges/{challenge_id}").status_code == 404
    assert client.post(
        f"/admin/challenges/{challenge_id}/publish",
        data={"csrf_token": csrf(client)},
        follow_redirects=False,
    ).status_code == 303
    edit_page = client.get(f"/admin/challenges/{challenge_id}/edit")
    assert "CTF{html_admin_flag}" not in edit_page.text
    assert client.post(
        f"/admin/challenges/{challenge_id}/edit",
        data={
            "csrf_token": csrf(client),
            "title": "HTML admin challenge",
            "category": "Crypto",
            "description": "Edited condition",
            "points": "81",
            "flag": "CTF{html_admin_flag_updated}",
            "is_published": "on",
            "resource_url": "/tasks/crypto01/download",
        },
        follow_redirects=False,
    ).status_code == 303

    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    register(client, "resetplayer")
    client.post(
        f"/api/challenges/{challenge_id}/submit",
        json={"flag": "CTF{html_admin_flag_updated}"},
        headers={"X-CSRF-Token": csrf(client)},
    )
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    token = csrf(client)
    assert client.post(
        "/api/auth/login",
        json={"username": "admin", "password": os.environ["ADMIN_PASSWORD"]},
        headers={"X-CSRF-Token": token},
    ).status_code == 200
    assert client.get("/api/scoreboard").json()[0]["score"] == 81
    assert client.delete(
        f"/api/admin/challenges/{challenge_id}",
        headers={"X-CSRF-Token": csrf(client)},
    ).status_code == 409
    assert client.post(
        "/admin/tournament/reset",
        data={"csrf_token": csrf(client)},
        follow_redirects=False,
    ).status_code == 303
    assert client.get("/api/scoreboard").json()[0]["score"] == 0
    assert client.get("/api/admin/submissions").json() == []
    assert client.delete(
        f"/api/admin/challenges/{challenge_id}",
        headers={"X-CSRF-Token": csrf(client)},
    ).status_code == 204


def test_solve_persists_after_reconnecting(client: TestClient):
    admin_client(client)
    challenge_id = create_challenge(client, "flag{persisted}", points=70)
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    register(client, "persistent")
    client.post(
        f"/api/challenges/{challenge_id}/submit",
        json={"flag": "flag{persisted}"},
        headers={"X-CSRF-Token": csrf(client)},
    )
    async def read_persisted_score():
        engine = create_async_engine(TEST_DATABASE_URL, pool_pre_ping=True)
        try:
            async with async_sessionmaker(engine, expire_on_commit=False)() as session:
                scores = await get_scoreboard(session)
                assert next(row["score"] for row in scores if row["username"] == "persistent") == 70
        finally:
            await engine.dispose()

    asyncio.run(read_persisted_score())
