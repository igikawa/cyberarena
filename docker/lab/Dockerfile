FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv/cyberarena
RUN pip install --no-cache-dir "fastapi>=0.115,<1" "uvicorn[standard]>=0.30,<1" "jinja2>=3.1,<4" "python-multipart>=0.0.9"
COPY --chown=10001:10001 app/__init__.py ./app/__init__.py
COPY --chown=10001:10001 app/lab ./app/lab
COPY --chown=10001:10001 templates/lab ./templates/lab
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.lab.main:app", "--host", "0.0.0.0", "--port", "8000"]