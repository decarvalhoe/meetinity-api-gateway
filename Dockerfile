# syntax=docker/dockerfile:1.4

#############################
# Builder image
#############################
FROM python:3.11-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt

#############################
# Runtime image
#############################
FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY . .

RUN addgroup --system meetinity \
    && adduser --system --ingroup meetinity --home /app meetinity \
    && chown -R meetinity:meetinity /app

USER meetinity

EXPOSE 8080

ENV GUNICORN_BIND=0.0.0.0:8080 \
    GUNICORN_WORKERS=4 \
    GUNICORN_THREADS=1 \
    GUNICORN_TIMEOUT=120 \
    GUNICORN_GRACEFUL_TIMEOUT=30 \
    GUNICORN_MAX_REQUESTS=0

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["sh", "-c", "exec gunicorn --bind ${GUNICORN_BIND:-0.0.0.0:8080} --workers ${GUNICORN_WORKERS:-4} --threads ${GUNICORN_THREADS:-1} --timeout ${GUNICORN_TIMEOUT:-120} --graceful-timeout ${GUNICORN_GRACEFUL_TIMEOUT:-30} --max-requests ${GUNICORN_MAX_REQUESTS:-0} src.main:app"]
