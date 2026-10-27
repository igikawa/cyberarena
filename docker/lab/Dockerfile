FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv/cyberarena
RUN python -m pip install --no-cache-dir "fastapi>=0.115,<1" "uvicorn[standard]>=0.30,<1" "jinja2>=3.1,<4" "python-multipart>=0.0.9" \
    && python -c "import fastapi, jinja2, multipart, uvicorn"
COPY --chown=10001:10001 binaries/revcheck /usr/local/bin/revcheck
COPY --chown=10001:10001 binaries/safevm /usr/local/bin/safevm
COPY --chown=10001:10001 app/__init__.py ./app/__init__.py
COPY --chown=10001:10001 app/http_errors.py ./app/http_errors.py
COPY --chown=10001:10001 app/lab ./app/lab
COPY --chown=10001:10001 templates/lab ./templates/lab
COPY --chown=10001:10001 templates/errors ./templates/errors
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.lab.main:app", "--host", "0.0.0.0", "--port", "8000"]