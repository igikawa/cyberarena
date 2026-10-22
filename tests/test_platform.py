import json
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.lab.main import app as lab_app
from app.platform.main import app as platform_app
from app.platform.models import DeletedChallengeSeed
from app.platform.services.scoreboard import get_scoreboard
from tests.conftest import (
    TEST_ADMIN_NEW_PASSWORD,
    TEST_DATABASE_URL,
    admin_client,
    create_challenge,
    csrf,
    register,
)


def test_registration_and_duplicate_username(client: TestClient):
    token = csrf(client)
    payload = {"username": "alice", "password": "long-password-123"}
    assert client.post("/api/auth/register", json=payload, headers={"X-CSRF-Token": token}).status_code == 201
    response = client.post("/api/auth/register", json=payload, headers={"X-CSRF-Token": token})
    assert response.status_code == 409


def test_challenge_sort_controls_and_profile_navigation(client: TestClient):
    register(client, "profileuser")
    listing = client.get("/challenges")
    assert "id=\"challenge-sort\"" in listing.text
    assert "value=\"title\">Названию" in listing.text
    assert "value=\"category\">Типу" in listing.text
    assert "value=\"status\">Статусу" in listing.text
    assert "data-status=\"unsolved\"" in listing.text
    assert "/static/challenges.js?v=2" in listing.text
    assert "Профиль" in listing.text
    assert "profileuser" not in listing.text
    assert "action=\"/logout\"" not in listing.text

    profile = client.get("/profile")
    assert profile.status_code == 200
    assert "profileuser" in profile.text
    assert "action=\"/logout\"" in profile.text
    assert "Выйти" in profile.text


def test_browser_errors_are_html_and_api_errors_negotiate_html_or_json(client: TestClient):
    html_404 = client.get("/missing-page", headers={"Accept": "text/html"})
    assert html_404.status_code == 404
    assert html_404.headers["content-type"].startswith("text/html")
    assert "Страница не найдена" in html_404.text
    assert "/errors/unavailable.css" in html_404.text

    api_404_html = client.get("/api/missing-route", headers={"Accept": "text/html"})
    assert api_404_html.status_code == 404
    assert api_404_html.headers["content-type"].startswith("text/html")
    assert "Страница не найдена" in api_404_html.text

    api_401_html = client.get("/api/admin/challenges", headers={"Accept": "text/html"})
    assert api_401_html.status_code == 401
    assert api_401_html.headers["content-type"].startswith("text/html")

    api_404_json = client.get("/api/missing-route", headers={"Accept": "application/json"})
    assert api_404_json.status_code == 404
    assert api_404_json.headers["content-type"].startswith("application/json")
    assert api_404_json.json() == {"detail": "Not Found"}

    register(client, "html403user")
    api_403_html = client.get("/api/admin/challenges", headers={"Accept": "text/html"})
    assert api_403_html.status_code == 403
    assert api_403_html.headers["content-type"].startswith("text/html")
    assert "Доступ запрещён" in api_403_html.text

    validation = client.post(
        "/api/auth/register",
        json={"username": "", "password": ""},
        headers={"Accept": "application/json", "X-CSRF-Token": csrf(client)},
    )
    assert validation.status_code == 422
    assert validation.headers["content-type"].startswith("application/json")
    assert "detail" in validation.json()


def test_lab_browser_errors_are_html():
    with TestClient(lab_app) as lab_client:
        response = lab_client.get("/documents/999", headers={"Accept": "text/html"})
    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")
    assert "Страница не найдена" in response.text


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


def test_admin_must_change_initial_password_before_using_platform(client: TestClient):
    login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": os.environ["ADMIN_PASSWORD"]},
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert login.status_code == 200
    assert login.json()["user"]["must_change_password"] is True
    assert client.get("/api/admin/challenges").status_code == 403

    mismatch = client.post(
        "/api/auth/admin/change-password",
        json={
            "current_password": os.environ["ADMIN_PASSWORD"],
            "new_password": TEST_ADMIN_NEW_PASSWORD,
            "confirm_password": "different-password",
        },
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert mismatch.status_code == 422

    changed = client.post(
        "/api/auth/admin/change-password",
        json={
            "current_password": os.environ["ADMIN_PASSWORD"],
            "new_password": TEST_ADMIN_NEW_PASSWORD,
            "confirm_password": TEST_ADMIN_NEW_PASSWORD,
        },
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert changed.status_code == 200
    assert client.get("/api/admin/challenges").status_code == 200
    assert client.get("/api/users/me").json()["must_change_password"] is False

    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    old_login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": os.environ["ADMIN_PASSWORD"]},
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert old_login.status_code == 401
    new_login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": TEST_ADMIN_NEW_PASSWORD},
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert new_login.status_code == 200
    assert new_login.json()["user"]["must_change_password"] is False


def test_admin_api_denies_regular_user(client: TestClient):
    register(client)
    response = client.get("/api/admin/challenges")
    assert response.status_code == 403


def test_openapi_docs_are_admin_only(client: TestClient):
    assert client.get("/docs").status_code == 401
    assert client.get("/openapi.json").status_code == 401

    register(client, "docsstudent")
    assert client.get("/docs").status_code == 403
    assert client.get("/openapi.json").status_code == 403

    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    admin_client(client)
    docs = client.get("/docs")
    schema = client.get("/openapi.json")
    assert docs.status_code == 200
    assert "/openapi.json" in docs.text
    assert schema.status_code == 200
    assert schema.json()["info"]["title"] == "CYBERARENA"
    assert "/api/challenges" in schema.json()["paths"]
    snapshot = json.loads((Path(__file__).resolve().parents[1] / "api" / "openapi.json").read_text())
    assert schema.json() == snapshot
    assert "/docs" not in schema.json()["paths"]
    assert "/openapi.json" not in schema.json()["paths"]


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
    assert response.headers["location"] == "/admin/change-password"
    password_page = client.get(response.headers["location"])
    assert password_page.status_code == 200
    changed = client.post(
        "/admin/change-password",
        data={
            "csrf_token": csrf(client),
            "current_password": os.environ["ADMIN_PASSWORD"],
            "new_password": TEST_ADMIN_NEW_PASSWORD,
            "confirm_password": TEST_ADMIN_NEW_PASSWORD,
        },
        follow_redirects=False,
    )
    assert changed.status_code == 303
    assert changed.headers["location"] == "/admin"
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
    assert "/static/tasks/web02/clue.js" in web02.text
    assert "<summary>Подсказка</summary>" in web02.text
    assert "CTF{source_maps_are_not_needed}" in script.text
    crypto = client.get("/tasks/crypto01/download")
    assert crypto.status_code == 200
    assert "attachment" in crypto.headers["content-disposition"]
    assert "FWI{fdhvdu_vkliw_lv_ixq}" in crypto.text


def test_rotating_seed_flags_updates_task_materials_and_validation(client: TestClient):
    admin_client(client)
    challenges = client.get("/api/admin/challenges").json()
    seeded = {
        challenge["resource_url"]: challenge["id"]
        for challenge in challenges
        if challenge["resource_url"] in {
            "/lab/",
            "/static/tasks/web02/index.html",
            "/tasks/crypto01/download",
        }
    }
    new_flags = {
        "/lab/": "CTF{web01_rotated_answer}",
        "/static/tasks/web02/index.html": "CTF{web02_rotated_answer}",
        "/tasks/crypto01/download": "CTF{crypto_rotated_answer}",
    }
    old_flags = {
        "/lab/": "CTF{idor_hidden_document}",
        "/static/tasks/web02/index.html": "CTF{source_maps_are_not_needed}",
        "/tasks/crypto01/download": "CTF{caesar_shift_is_fun}",
    }
    assert set(seeded) == set(new_flags)
    for resource_url, flag in new_flags.items():
        response = client.patch(
            f"/api/admin/challenges/{seeded[resource_url]}",
            json={"flag": flag},
            headers={"X-CSRF-Token": csrf(client)},
        )
        assert response.status_code == 200, response.text

    with TestClient(lab_app) as lab:
        web01_document = lab.get("/documents/1002").text
        assert new_flags["/lab/"] in web01_document
        assert old_flags["/lab/"] not in web01_document

    web02_page = client.get("/static/tasks/web02/index.html")
    web02_script = client.get("/static/tasks/web02/clue.js")
    assert "/static/tasks/web02/clue.js" in web02_page.text
    assert new_flags["/static/tasks/web02/index.html"] in web02_script.text
    assert old_flags["/static/tasks/web02/index.html"] not in web02_script.text

    crypto_text = client.get("/tasks/crypto01/download").text
    encoded_flag = crypto_text.split("Ciphertext: ", 1)[1].strip()
    decoded_flag = "".join(
        chr((ord(char) - ord("A" if char.isupper() else "a") - 3) % 26 + ord("A" if char.isupper() else "a"))
        if char.isascii() and char.isalpha()
        else char
        for char in encoded_flag
    )
    assert decoded_flag == new_flags["/tasks/crypto01/download"]
    assert decoded_flag != old_flags["/tasks/crypto01/download"]

    for resource_url, flag in new_flags.items():
        old_response = client.post(
            f"/api/challenges/{seeded[resource_url]}/submit",
            json={"flag": old_flags[resource_url]},
            headers={"X-CSRF-Token": csrf(client)},
        )
        assert old_response.status_code == 200
        assert old_response.json()["is_correct"] is False
        response = client.post(
            f"/api/challenges/{seeded[resource_url]}/submit",
            json={"flag": flag},
            headers={"X-CSRF-Token": csrf(client)},
        )
        assert response.status_code == 200
        assert response.json()["is_correct"] is True


def test_isolated_web_lab_idor_and_allowlisted_documents(client: TestClient):
    with TestClient(lab_app) as lab:
        home = lab.get("/")
        assert home.status_code == 200
        assert "WEB · IDOR" in home.text
        assert "SQL" in home.text
        assert "Начать исследование" in home.text
        document = lab.get("/documents/1001")
        assert document.status_code == 200
        assert "<summary>Подсказка</summary>" in document.text
        exposed = lab.get("/documents/1002")
        assert exposed.status_code == 200
        assert "CTF{idor_hidden_document}" in exposed.text
        assert lab.get("/documents/1003").status_code == 404


def test_new_lab_challenges_are_isolated_and_flags_rotate(client: TestClient):
    admin_client(client)
    challenge_by_seed_url = {
        challenge["resource_url"]: challenge["id"]
        for challenge in client.get("/api/admin/challenges").json()
    }
    lab_urls = {
        "/lab/sql/": ("web-03-sqli", "CTF{union_of_synthetic_records}", "CTF{sql_rotated}"),
        "/lab/files/": ("web-04-path-traversal", "CTF{virtual_paths_only}", "CTF{path_rotated}"),
        "/lab/shop/": ("business-01", "CTF{negative_quantity_credit}", "CTF{business_rotated}"),
    }
    with TestClient(lab_app) as lab:
        assert "/lab/sql/" in lab.get("/").text
        normal_search = lab.get("/sql/", params={"username": "maria"})
        assert "CTF{" not in normal_search.text
        assert "<summary>Подсказка</summary>" in normal_search.text
        sql_injection = lab.get("/sql/", params={"username": "' OR 1=1 --"})
        assert sql_injection.status_code == 200
        assert "CTF{union_of_synthetic_records}" in sql_injection.text

        public_file = lab.get("/files/", params={"path": "readme.txt"})
        assert "Публичная папка лаборатории" in public_file.text
        assert "<summary>Подсказка</summary>" in public_file.text
        traversal = lab.get("/files/", params={"path": "../../private/flag.txt"})
        assert traversal.status_code == 200
        assert "CTF{virtual_paths_only}" in traversal.text
        assert "README.md" not in traversal.text
        outside_virtual_files = lab.get("/files/", params={"path": "../../etc/passwd"})
        assert "Файл не найден" in outside_virtual_files.text
        assert "root:" not in outside_virtual_files.text

        normal_purchase = lab.post("/shop/checkout", data={"quantity": "1"})
        assert normal_purchase.status_code == 200
        assert "Недостаточно кредитов" in normal_purchase.text
        assert "<summary>Подсказка</summary>" in normal_purchase.text
        exploit_purchase = lab.post("/shop/checkout", data={"quantity": "-1"})
        assert exploit_purchase.status_code == 200
        assert "CTF{negative_quantity_credit}" in exploit_purchase.text
        invalid_purchase = lab.post("/shop/checkout", data={"quantity": "not-a-number"})
        assert invalid_purchase.status_code == 422
        assert "Количество должно быть целым числом" in invalid_purchase.text
        missing_quantity = lab.post("/shop/checkout", data={})
        assert missing_quantity.status_code == 422
        assert "Количество должно быть целым числом" in missing_quantity.text

    for index, (resource_url, (_, old_flag, new_flag)) in enumerate(lab_urls.items()):
        challenge_id = challenge_by_seed_url[resource_url]
        changed = client.patch(
            f"/api/admin/challenges/{challenge_id}",
            json={"flag": new_flag},
            headers={"X-CSRF-Token": csrf(client)},
        )
        assert changed.status_code == 200, changed.text
        with TestClient(lab_app) as lab:
            if resource_url == "/lab/sql/":
                material = lab.get("/sql/", params={"username": "' OR 1=1 --"}).text
            elif resource_url == "/lab/files/":
                material = lab.get("/files/", params={"path": "../../private/flag.txt"}).text
            else:
                material = lab.post("/shop/checkout", data={"quantity": "-1"}).text
        assert new_flag in material
        assert old_flag not in material

        with TestClient(platform_app) as player:
            register(player, f"solver{index}")
            rejected = player.post(
                f"/api/challenges/{challenge_id}/submit",
                json={"flag": old_flag},
                headers={"X-CSRF-Token": csrf(player)},
            )
            accepted = player.post(
                f"/api/challenges/{challenge_id}/submit",
                json={"flag": new_flag},
                headers={"X-CSRF-Token": csrf(player)},
            )
            assert rejected.status_code == 200 and rejected.json()["is_correct"] is False
            assert accepted.status_code == 200 and accepted.json()["is_correct"] is True


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
        json={"username": "admin", "password": TEST_ADMIN_NEW_PASSWORD},
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


def test_redis_cache_hits_and_invalidates_for_challenges_and_scoreboard(client: TestClient):
    class MemoryRedis:
        def __init__(self):
            self.values = {}
            self.reads = 0

        async def get(self, key):
            self.reads += 1
            return self.values.get(key)

        async def set(self, key, value, ex):
            assert ex == 15
            self.values[key] = value

        async def delete(self, *keys):
            for key in keys:
                self.values.pop(key, None)

        async def incr(self, key):
            value = int(self.values.get(key, "0")) + 1
            self.values[key] = str(value)
            return value

    cache = MemoryRedis()
    client.app.state.redis = cache
    admin_client(client)
    challenge_id = create_challenge(client, "CTF{cached-solve}", points=50)

    first = client.get("/api/challenges").json()
    second = client.get("/api/challenges").json()
    assert first == second
    assert cache.reads == 5

    from app.platform.services.cache import (
        CHALLENGES_CACHE_KEY,
        get_json_cache,
        invalidate_challenges_cache,
        set_json_cache,
    )

    async def reject_outdated_cache_writer():
        stale_read = await get_json_cache(cache, CHALLENGES_CACHE_KEY, list)
        assert stale_read.value is not None
        assert [item["id"] for item in stale_read.value] == [item["id"] for item in first]
        await invalidate_challenges_cache(cache)
        await set_json_cache(
            cache,
            CHALLENGES_CACHE_KEY,
            [{"id": -1}],
            stale_read.generation,
        )
        current_read = await get_json_cache(cache, CHALLENGES_CACHE_KEY, list)
        assert current_read.value is None

    asyncio.run(reject_outdated_cache_writer())
    assert client.get("/api/challenges").json() == first

    added_id = create_challenge(client, "CTF{cache-create}")
    added = client.get("/api/challenges").json()
    assert added[-1]["id"] == added_id

    token = csrf(client)
    assert client.post(
        f"/api/admin/challenges/{added_id}/unpublish",
        headers={"X-CSRF-Token": token},
    ).status_code == 200
    assert added_id not in {item["id"] for item in client.get("/api/challenges").json()}
    assert client.post(
        f"/api/admin/challenges/{added_id}/publish",
        headers={"X-CSRF-Token": csrf(client)},
    ).status_code == 200
    assert added_id in {item["id"] for item in client.get("/api/challenges").json()}
    assert client.post(
        f"/admin/challenges/{added_id}/unpublish",
        data={"csrf_token": csrf(client)},
        follow_redirects=False,
    ).status_code == 303
    assert added_id not in {item["id"] for item in client.get("/api/challenges").json()}
    assert client.post(
        f"/admin/challenges/{added_id}/publish",
        data={"csrf_token": csrf(client)},
        follow_redirects=False,
    ).status_code == 303
    assert added_id in {item["id"] for item in client.get("/api/challenges").json()}

    deleted_id = create_challenge(client, "CTF{cache-delete}")
    assert client.delete(
        f"/api/admin/challenges/{deleted_id}",
        headers={"X-CSRF-Token": csrf(client)},
    ).status_code == 204
    assert deleted_id not in {item["id"] for item in client.get("/api/challenges").json()}

    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    register(client, "cacheplayer")
    assert client.get("/api/challenges").json()[-1]["is_solved"] is False
    solved = client.post(
        f"/api/challenges/{challenge_id}/submit",
        json={"flag": "CTF{cached-solve}"},
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert solved.json()["status"] == "correct"
    assert client.get(f"/api/challenges/{challenge_id}").json()["is_solved"] is True

    scoreboard = client.get("/api/scoreboard").json()
    assert next(row["score"] for row in scoreboard if row["username"] == "cacheplayer") == 50
    assert client.get("/scoreboard").status_code == 200

    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": TEST_ADMIN_NEW_PASSWORD},
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert login.status_code == 200
    updated = client.patch(
        f"/api/admin/challenges/{challenge_id}",
        json={"points": 75},
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert updated.status_code == 200
    assert client.get(f"/api/challenges/{challenge_id}").json()["points"] == 75
    scoreboard = client.get("/api/scoreboard").json()
    assert next(row["score"] for row in scoreboard if row["username"] == "cacheplayer") == 75

    assert client.post(
        "/api/admin/tournament/reset",
        headers={"X-CSRF-Token": csrf(client)},
    ).status_code == 200
    scoreboard = client.get("/api/scoreboard").json()
    assert next(row["score"] for row in scoreboard if row["username"] == "cacheplayer") == 0
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    player_login = client.post(
        "/api/auth/login",
        json={"username": "cacheplayer", "password": "user-password-123"},
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert player_login.status_code == 200
    client.post(
        f"/api/challenges/{challenge_id}/submit",
        json={"flag": "CTF{cached-solve}"},
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert next(
        row["score"]
        for row in client.get("/api/scoreboard").json()
        if row["username"] == "cacheplayer"
    ) == 75
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf(client)})
    admin_login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": TEST_ADMIN_NEW_PASSWORD},
        headers={"X-CSRF-Token": csrf(client)},
    )
    assert admin_login.status_code == 200
    assert client.post(
        "/admin/tournament/reset",
        data={"csrf_token": csrf(client)},
        follow_redirects=False,
    ).status_code == 303
    assert next(
        row["score"]
        for row in client.get("/api/scoreboard").json()
        if row["username"] == "cacheplayer"
    ) == 0

    from redis.exceptions import RedisError

    class UnavailableRedis:
        async def get(self, key):
            raise RedisError("test Redis outage")

        async def set(self, key, value, ex):
            raise RedisError("test Redis outage")

        async def incr(self, key):
            raise RedisError("test Redis outage")

    client.app.state.redis = UnavailableRedis()
    assert client.get("/api/challenges").status_code == 200
    scoreboard = client.get("/api/scoreboard").json()
    assert next(row["score"] for row in scoreboard if row["username"] == "cacheplayer") == 0
