import json
import os
import posixpath
import sqlite3
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.http_errors import register_error_handlers

app = FastAPI(title="CYBERARENA Web Lab", docs_url=None, redoc_url=None)
register_error_handlers(app)
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


def render_lab_page(
    request: Request,
    template_name: str,
    context: dict,
    status_code: int = 200,
) -> HTMLResponse:
    response = templates.TemplateResponse(
        request,
        template_name,
        context,
        status_code=status_code,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health", include_in_schema=False)
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def lab_home(request: Request) -> HTMLResponse:
    return render_lab_page(request, "home.html", {})


@app.get("/documents/{document_id}", response_class=HTMLResponse)
async def document(document_id: int, request: Request) -> HTMLResponse:
    documents = {
        1001: ("Инструкция для сотрудников", "Тестовая запись. Документ 1002 принадлежит руководителю отдела."),
        1002: ("Личный документ руководителя", "Заметка для учебного задания."),
    }
    selected = documents.get(document_id)
    if selected is None:
        raise HTTPException(status_code=404, detail="Document not found")
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
async def employee_search(request: Request, username: str = "") -> HTMLResponse:
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
        message = "Запрос не удалось выполнить."
    else:
        message = None
    finally:
        connection.close()
    return render_lab_page(
        request,
        "sql.html",
        {
            "username": username,
            "rows": rows,
            "message": message,
        },
    )


@app.get("/files/", response_class=HTMLResponse)
async def virtual_file_viewer(request: Request, path: str = "") -> HTMLResponse:
    virtual_files = {
        "/public/manual/readme.txt": "Публичная папка лаборатории. В ней находятся только учебные файлы.",
        "/private/flag.txt": f"Флаг: {lab_flag('web-04-path-traversal')}",
    }
    resolved_path = posixpath.normpath(posixpath.join("/public/manual", path))
    content_value = virtual_files.get(resolved_path)
    return render_lab_page(
        request,
        "files.html",
        {"path": path, "content_value": content_value},
    )


@app.get("/shop/", response_class=HTMLResponse)
async def shop(request: Request) -> HTMLResponse:
    return render_lab_page(request, "shop.html", {"result": None})


@app.post("/shop/checkout", response_class=HTMLResponse)
async def shop_checkout(request: Request) -> HTMLResponse:
    form = await request.form()
    try:
        quantity = int(str(form.get("quantity", "")))
    except ValueError:
        raise HTTPException(
            status_code=422, detail="Количество должно быть целым числом"
        )
    balance = 100
    unit_price = 250
    total = unit_price * quantity
    if balance < total:
        result = f"Недостаточно кредитов: заказ стоит {total}, баланс — {balance}."
        return render_lab_page(request, "shop.html", {"result": result})
    flag = lab_flag("business-01")
    result = (
        f"Заказ оформлен. Количество: {quantity}; списано: {total} кредитов. "
        f"Содержимое премиального пропуска: {flag}"
    )
    return render_lab_page(request, "shop.html", {"result": result})