FROM python:3.12-slim AS binary-build
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY docker/lab/binaries/revcheck.c docker/lab/binaries/safevm.c ./
RUN mkdir /out \
    && gcc -O2 -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
        -Wall -Wextra -Wconversion -Wformat=2 -Wshadow -Werror \
        revcheck.c -o /out/revcheck \
    && gcc -O2 -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
        -Wall -Wextra -Wconversion -Wformat=2 -Wshadow -Werror \
        safevm.c -o /out/safevm \
    && strip /out/revcheck /out/safevm

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv/lab-manager
COPY docker/lab-manager/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY lab-manager/lab_manager ./lab_manager
COPY docker/lab/Dockerfile /opt/lab-build/Dockerfile
COPY app/__init__.py app/http_errors.py /opt/lab-build/app/
COPY app/lab /opt/lab-build/app/lab
COPY templates/lab /opt/lab-build/templates/lab
COPY templates/errors /opt/lab-build/templates/errors
COPY --from=binary-build /out/revcheck /opt/lab-build/binaries/revcheck
COPY --from=binary-build /out/safevm /opt/lab-build/binaries/safevm
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "lab_manager.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
