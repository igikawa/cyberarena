import html
import json
import os
import posixpath
import sqlite3
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

app = FastAPI(title="CYBERARENA Web Lab", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[2] / "templates" / "lab"))
LAB_FLAGS_FILE = Path(os.getenv("LAB_FLAGS_FILE", "/tmp/cyberarena-lab-flags.json"))


def lab_flag(seed_key: str) -> str:
    try:
        flags = json.loads(LAB_FLAGS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail="Challenge material is unavailable") from exc
    flag = flags.get(seed_key) if isinstance(flags, dict) else None
    if not isinstance(flag, str):
        raise HTTPException(status_code=503, detail="Challenge material is unavailable")
    return flag


def task_page(title: str, content: str, status_code: int = 200) -> HTMLResponse:
    body = (
        "<!doctype html><html lang='ru'><meta charset='utf-8'>"
        f"<title>{html.escape(title)} · CYBERARENA lab</title>"
        "<style>body{max-width:800px;margin:3rem auto;padding:0 1rem;"
        "font:16px system-ui;background:#09111a;color:#eaf4f3}"
        "a{color:#61e5b5}input,button{padding:.5rem;margin:.25rem}"
        "pre{white-space:pre-wrap;background:#101d27;padding:1rem}</style>"
        f"<p><a href='/lab/'>← Лаборатория</a></p><h1>{html.escape(title)}</h1>"
        f"{content}</html>"
    )
    return HTMLResponse(
        body,
        status_code=status_code,
        headers={"Cache-Control": "no-store"},
    )


@app.get("/health", include_in_schema=False)
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def lab_home(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "home.html", {})


@app.get("/documents/{document_id}", response_class=HTMLResponse)
async def document(document_id: int, request: Request) -> HTMLResponse:
    documents = {
        1001: ("Инструкция для сотрудников", "Тестовая запись. Документ 1002 принадлежит руководителю отдела."),
        1002: ("Личный документ руководителя", "Заметка для учебного задания."),
    }
    selected = documents.get(document_id)
    if selected is None:
        return HTMLResponse("<h1>Документ не найден</h1>", status_code=404)
    title, body = selected
    if document_id == 1002:
        body = f"{body} Флаг: {lab_flag('web-01')}"
    response = templates.TemplateResponse(
        request,
        "document.html",
        {"title": title, "body": body},
    )
    if document_id == 1002:
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/sql/", response_class=HTMLResponse)
async def employee_search(username: str = "") -> HTMLResponse:
    flag = lab_flag("web-03-sqli")
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE employees (username TEXT, note TEXT)")
        connection.executemany(
            "INSERT INTO employees VALUES (?, ?)",
            (
                ("maria", "Сотрудник отдела закупок"),
                ("ivan", "Сотрудник технической поддержки"),
                ("auditor", f"Закрытая заметка: {flag}"),
            ),
        )
        # This intentionally vulnerable query is limited to synthetic in-memory data.
        query = f"SELECT username, note FROM employees WHERE username = '{username}'"
        rows = connection.execute(query).fetchall()
    except sqlite3.Error:
        rows = []
        message = "<p>Запрос не удалось выполнить.</p>"
    else:
        message = ""
    finally:
        connection.close()
    results = "".join(
        f"<li><strong>{html.escape(username_value)}</strong>: {html.escape(note)}</li>"
        for username_value, note in rows
    ) or "<li>Записей не найдено.</li>"
    content = (
        "<p>Найдите сотрудника в локальном тестовом каталоге.</p>"
        "<form><label>Имя пользователя "
        f"<input name='username' value='{html.escape(username, quote=True)}'></label>"
        "<button>Искать</button></form>"
        f"{message}<ul>{results}</ul>"
    )
    return task_page("WEB-03 — Архив сотрудников", content)


@app.get("/files/", response_class=HTMLResponse)
async def virtual_file_viewer(path: str = "") -> HTMLResponse:
    virtual_files = {
        "/public/manual/readme.txt": "Публичная папка лаборатории. В ней находятся только учебные файлы.",
        "/private/flag.txt": f"Флаг: {lab_flag('web-04-path-traversal')}",
    }
    resolved_path = posixpath.normpath(posixpath.join("/public/manual", path))
    content_value = virtual_files.get(resolved_path)
    content = (
        "<p>Просмотрщик читает файлы из публичной папки лаборатории.</p>"
        "<form><label>Путь к файлу "
        f"<input name='path' value='{html.escape(path, quote=True)}'></label>"
        "<button>Открыть</button></form>"
    )
    if content_value is None:
        content += "<p>Файл не найден.</p>"
    else:
        content += f"<pre>{html.escape(content_value)}</pre>"
    return task_page("WEB-04 — За пределами папки", content)


@app.get("/shop/", response_class=HTMLResponse)
async def shop() -> HTMLResponse:
    content = (
        "<p>Учебный баланс: 100 кредитов. Премиальный пропуск стоит 250 кредитов.</p>"
        "<form method='post' action='/lab/shop/checkout'>"
        "<label>Количество "
        "<input name='quantity' type='number' value='1' required></label>"
        "<button>Оформить заказ</button></form>"
    )
    return task_page("BIZ-01 — Магазин с ошибкой", content)


@app.post("/shop/checkout", response_class=HTMLResponse)
async def shop_checkout(request: Request) -> HTMLResponse:
    form = await request.form()
    try:
        quantity = int(str(form.get("quantity", "")))
    except ValueError:
        return task_page(
            "BIZ-01 — Магазин с ошибкой",
            "<p>Количество должно быть целым числом.</p>",
            status_code=422,
        )
    balance = 100
    unit_price = 250
    total = unit_price * quantity
    if balance < total:
        content = f"<p>Недостаточно кредитов: заказ стоит {total}, баланс — {balance}.</p>"
        return task_page("BIZ-01 — Магазин с ошибкой", content)
    flag = lab_flag("business-01")
    content = (
        f"<p>Заказ оформлен. Количество: {quantity}; списано: {total} кредитов.</p>"
        f"<p>Содержимое премиального пропуска: {html.escape(flag)}</p>"
    )
    return task_page("BIZ-01 — Магазин с ошибкой", content)