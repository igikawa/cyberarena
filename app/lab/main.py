import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

app = FastAPI(title="CYBERARENA Web Lab", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[2] / "templates" / "lab"))
LAB_FLAGS_FILE = Path(os.getenv("LAB_FLAGS_FILE", "/tmp/cyberarena-lab-flags.json"))


def web01_flag() -> str:
    try:
        flags = json.loads(LAB_FLAGS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail="Challenge material is unavailable") from exc
    flag = flags.get("web-01") if isinstance(flags, dict) else None
    if not isinstance(flag, str):
        raise HTTPException(status_code=503, detail="Challenge material is unavailable")
    return flag


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
        body = f"{body} Флаг: {web01_flag()}"
    response = templates.TemplateResponse(
        request,
        "document.html",
        {"title": title, "body": body},
    )
    if document_id == 1002:
        response.headers["Cache-Control"] = "no-store"
    return response