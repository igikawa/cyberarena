from pathlib import Path
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from fastapi import Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

ERROR_TEMPLATES = Jinja2Templates(
    directory=str(Path(__file__).resolve().parents[1] / "templates" / "errors")
)

ERROR_CONTENT: dict[int, tuple[str, str, str, str]] = {
    400: (
        "Некорректный запрос",
        "Не удалось понять запрос",
        "Похоже, запрос содержит некорректные данные или был отправлен в неожиданном формате.",
        "Проверьте данные и попробуйте ещё раз.",
    ),
    401: (
        "Нужен вход",
        "Сначала войдите",
        "Эта страница доступна только после входа в аккаунт.",
        "После входа вы сможете продолжить работу.",
    ),
    403: (
        "Доступ запрещён",
        "У вас нет доступа",
        "Для просмотра этой страницы не хватает прав. Если доступ необходим для турнира, обратитесь к администратору.",
        "Доступ к закрытым разделам определяется ролью аккаунта.",
    ),
    404: (
        "Страница не найдена",
        "Похоже, здесь пусто",
        "Такой страницы нет: возможно, ссылка устарела или адрес был введён с ошибкой.",
        "Вернитесь на платформу и выберите нужный раздел.",
    ),
    405: (
        "Метод не поддерживается",
        "Так нельзя открыть эту страницу",
        "Для этого адреса не поддерживается использованный способ запроса. Откройте страницу обычной ссылкой.",
        "Если ошибка повторяется, сообщите администратору.",
    ),
    408: (
        "Время ожидания истекло",
        "Запрос задержался",
        "Сервер не дождался запроса целиком. Проверьте соединение и попробуйте отправить его ещё раз.",
        "Ваш прогресс сохранён.",
    ),
    409: (
        "Конфликт данных",
        "Изменение не удалось",
        "Запрос конфликтует с текущим состоянием данных. Обновите страницу и проверьте, не изменилось ли содержимое.",
        "Если конфликт сохраняется, обратитесь к администратору.",
    ),
    410: (
        "Материал удалён",
        "Этого материала больше нет",
        "Страница или задание были удалены и больше недоступны по этой ссылке.",
        "Здесь доступны только актуальные материалы турнира.",
    ),
    413: (
        "Слишком большой запрос",
        "Файл не поместился",
        "Размер отправленных данных превышает допустимый для платформы. Уменьшите объём и повторите попытку.",
        "Максимальный размер запроса ограничен для безопасности платформы.",
    ),
    414: (
        "Слишком длинный адрес",
        "Ссылка получилась слишком длинной",
        "Адрес запроса превышает допустимую длину. Удалите лишние параметры или откройте нужный раздел с главной страницы.",
        "Параметры запроса не должны содержать большие объёмы данных.",
    ),
    415: (
        "Формат не поддерживается",
        "Неизвестный формат данных",
        "Платформа не может обработать отправленный формат. Проверьте тип содержимого запроса и попробуйте снова.",
        "Используйте форму, предусмотренную для этого действия.",
    ),
    422: (
        "Проверьте введённые данные",
        "Проверьте заполненные поля",
        "Некоторые значения отсутствуют или не подходят по формату. Вернитесь к форме, исправьте их и отправьте ещё раз.",
        "Введённые данные не были приняты.",
    ),
    429: (
        "Слишком много запросов",
        "Небольшая пауза",
        "За короткое время поступило слишком много запросов. Подождите немного, прежде чем повторить действие.",
        "Ограничение помогает сохранить платформу доступной для всех.",
    ),
    431: (
        "Заголовки запроса слишком велики",
        "Запрос не поместился",
        "Заголовки запроса превышают допустимый размер. Очистите cookies сайта или откройте его в новом приватном окне.",
        "Это часто помогает, если браузер накопил слишком много данных сайта.",
    ),
}


def wants_html_error(request: Request) -> bool:
    if request.url.path == "/openapi.json":
        return False

    is_api_request = request.url.path == "/api" or request.url.path.startswith("/api/")
    accepted_types: dict[str, float] = {}
    for accepted_type in request.headers.get("accept", "").split(","):
        media_type, *parameters = accepted_type.strip().lower().split(";")
        quality = 1.0
        for parameter in parameters:
            name, separator, value = parameter.strip().partition("=")
            if name == "q" and separator:
                try:
                    quality = float(value)
                except ValueError:
                    quality = 0.0
                break
        accepted_types[media_type] = quality

    html_quality = accepted_types.get("text/html", 0.0)
    json_quality = accepted_types.get("application/json", 0.0)
    if html_quality > 0 and html_quality > json_quality:
        return True
    if is_api_request:
        return False

    content_type = request.headers.get("content-type", "")
    return content_type.startswith("application/x-www-form-urlencoded")


def register_error_handlers(app: Any) -> None:
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> HTMLResponse | JSONResponse:
        if not wants_html_error(request):
            return JSONResponse(
                status_code=exc.status_code,
                content=jsonable_encoder({"detail": exc.detail}),
                headers=exc.headers,
            )
        message = exc.detail if exc.status_code == 422 and isinstance(exc.detail, str) else None
        return render_error_page(request, exc.status_code, exc.headers, message)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> HTMLResponse | JSONResponse:
        if not wants_html_error(request):
            return JSONResponse(
                status_code=422,
                content=jsonable_encoder({"detail": exc.errors()}),
            )
        return render_error_page(request, 422)


def render_error_page(
    request: Request,
    status_code: int,
    headers: Mapping[str, str] | None = None,
    message_override: str | None = None,
) -> HTMLResponse:
    eyebrow, title, message, hint = ERROR_CONTENT.get(
        status_code,
        (
            "Ошибка запроса",
            "Не удалось выполнить запрос",
            "Попробуйте повторить действие. Если ошибка сохраняется, сообщите администратору.",
            "Ваши данные не были изменены.",
        ),
    )
    if message_override is not None:
        message = message_override
    referer = request.headers.get("referer", "")
    parsed_referer = urlsplit(referer)
    back_url = (
        urlunsplit(("", "", parsed_referer.path, parsed_referer.query, ""))
        if parsed_referer.netloc == request.url.netloc and parsed_referer.path.startswith("/")
        else "/"
    )
    return ERROR_TEMPLATES.TemplateResponse(
        request,
        "http_error.html",
        {
            "status_code": status_code,
            "eyebrow": eyebrow,
            "title": title,
            "message": message,
            "hint": hint,
            "back_url": back_url,
        },
        status_code=status_code,
        headers={"Cache-Control": "no-store", **(headers or {})},
    )
