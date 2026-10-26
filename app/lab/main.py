import os
import posixpath
import re
import sqlite3
import subprocess
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from app.http_errors import register_error_handlers

app = FastAPI(title="CYBERARENA Web Lab", docs_url=None, redoc_url=None)
register_error_handlers(app)
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[2] / "templates" / "lab"))
MaterialKey = Literal[
    "web-01",
    "web-03-sqli",
    "web-04-path-traversal",
    "business-01",
    "reverse-01",
    "pwn-01",
]
LAB_CHALLENGE_KEY = os.getenv("LAB_CHALLENGE_KEY")
LAB_CHALLENGE_FLAG = os.getenv("LAB_CHALLENGE_FLAG")
app.state.challenge_key = LAB_CHALLENGE_KEY
LAB_MATERIALS: dict[str, str] = (
    {LAB_CHALLENGE_KEY: LAB_CHALLENGE_FLAG}
    if LAB_CHALLENGE_KEY
    in {
        "web-01",
        "web-03-sqli",
        "web-04-path-traversal",
        "business-01",
        "reverse-01",
        "pwn-01",
    }
    and LAB_CHALLENGE_FLAG
    else {}
)


@app.middleware("http")
async def set_lab_base_path(request: Request, call_next):
    prefix = request.headers.get("x-lab-base-path", "")
    if not re.fullmatch(r"/lab-session/[A-Za-z0-9_-]{40,64}", prefix):
        prefix = ""
    request.scope["lab_base_path"] = prefix
    return await call_next(request)


def lab_flag(seed_key: MaterialKey) -> str:
    flag = LAB_MATERIALS.get(seed_key)
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
        {"lab_base_path": request.scope.get("lab_base_path", ""), **context},
        status_code=status_code,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health", include_in_schema=False)
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def lab_home(request: Request) -> HTMLResponse:
    return render_lab_page(
        request,
        "home.html",
        {"challenge_key": LAB_CHALLENGE_KEY},
    )


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
        {
            "title": title,
            "body": body,
            "lab_base_path": request.scope.get("lab_base_path", ""),
        },
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


def require_binary_challenge(challenge_key: str, request: Request) -> str:
    if request.app.state.challenge_key != challenge_key:
        raise HTTPException(status_code=404, detail="Challenge resource not found")
    return challenge_key


def run_binary(binary_name: str, value: str) -> bool:
    if "\x00" in value:
        raise HTTPException(status_code=422, detail="Input contains an unsupported character")
    try:
        result = subprocess.run(
            [f"/usr/local/bin/{binary_name}", value],
            capture_output=True,
            text=True,
            timeout=1,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=503, detail="Binary checker timed out") from exc
    except OSError as exc:
        raise HTTPException(status_code=503, detail="Binary checker is unavailable") from exc
    if result.returncode not in {0, 1}:
        raise HTTPException(status_code=503, detail="Binary checker failed")
    return result.returncode == 0


def binary_page(
    request: Request,
    title: str,
    task: str,
    result: str | None = None,
) -> HTMLResponse:
    return render_lab_page(
        request,
        "binary.html",
        {
            "title": title,
            "task": task,
            "result": result,
        },
    )


@app.get("/reverse/", response_class=HTMLResponse)
async def reverse_page(request: Request) -> HTMLResponse:
    require_binary_challenge("reverse-01", request)
    return binary_page(
        request,
        "REV-01 — Машина состояний",
        "reverse",
    )


@app.get("/reverse/download")
async def reverse_download(request: Request) -> FileResponse:
    require_binary_challenge("reverse-01", request)
    return FileResponse(
        "/usr/local/bin/revcheck",
        media_type="application/octet-stream",
        filename="revcheck",
        headers={"Cache-Control": "no-store"},
    )


@app.post("/reverse/submit", response_class=HTMLResponse)
async def reverse_submit(
    request: Request,
    answer: str = Form(max_length=48),
) -> HTMLResponse:
    require_binary_challenge("reverse-01", request)
    if len(answer.encode("utf-8")) > 48:
        raise HTTPException(status_code=422, detail="Answer is too long")
    accepted = await run_in_threadpool(run_binary, "revcheck", answer)
    result = (
        f"Верно. Флаг: {lab_flag('reverse-01')}"
        if accepted
        else "Пока не подходит. Продолжайте анализ бинарника."
    )
    return binary_page(
        request,
        "REV-01 — Машина состояний",
        "reverse",
        result,
    )


@app.get("/pwn/", response_class=HTMLResponse)
async def pwn_page(request: Request) -> HTMLResponse:
    require_binary_challenge("pwn-01", request)
    return binary_page(
        request,
        "PWN-01 — Пульт управления",
        "pwn",
    )


@app.get("/pwn/download")
async def pwn_download(request: Request) -> FileResponse:
    require_binary_challenge("pwn-01", request)
    return FileResponse(
        "/usr/local/bin/safevm",
        media_type="application/octet-stream",
        filename="safevm",
        headers={"Cache-Control": "no-store"},
    )


@app.post("/pwn/submit", response_class=HTMLResponse)
async def pwn_submit(
    request: Request,
    program: str = Form(max_length=128),
) -> HTMLResponse:
    require_binary_challenge("pwn-01", request)
    if len(program.encode("utf-8")) > 128:
        raise HTTPException(status_code=422, detail="Program is too long")
    accepted = await run_in_threadpool(run_binary, "safevm", program)
    result = (
        f"Состояние достигнуто. Флаг: {lab_flag('pwn-01')}"
        if accepted
        else "Целевое состояние не достигнуто."
    )
    return binary_page(
        request,
        "PWN-01 — Пульт управления",
        "pwn",
        result,
    )