from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

app = FastAPI(title="CYBERARENA Web Lab", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[2] / "templates" / "lab"))


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
        1002: ("Личный документ руководителя", "Заметка для учебного задания. Флаг: CTF{idor_hidden_document}"),
    }
    selected = documents.get(document_id)
    if selected is None:
        return HTMLResponse("<h1>Документ не найден</h1>", status_code=404)
    title, body = selected
    return templates.TemplateResponse(
        request,
        "document.html",
        {"title": title, "body": body},
    )