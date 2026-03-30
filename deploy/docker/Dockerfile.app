# Multi-stage Dockerfile for core-graph Python application.
# Serves REST API, MCP server, graph writer, and DLQ processor
# via command override.

# ---------- Stage 1: build ----------
FROM python:3.14-slim AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY api/ api/
COPY ingest/ ingest/
COPY evidence/ evidence/
COPY scripts/ scripts/

# ---------- Stage 2: runtime ----------
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update -qq \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 10001 cg && useradd -u 10001 -g cg -s /usr/sbin/nologin cg

WORKDIR /app

COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin /usr/local/bin
COPY --from=build /app/api api/
COPY --from=build /app/ingest ingest/
COPY --from=build /app/evidence evidence/
COPY --from=build /app/scripts scripts/

USER cg

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD curl -sf http://localhost:8000/healthz || exit 1

EXPOSE 8000

LABEL org.opencontainers.image.source="https://github.com/rmednitzer/core-graph" \
      org.opencontainers.image.title="core-graph"

ENTRYPOINT ["uvicorn", "api.rest.main:app", "--host", "0.0.0.0", "--port", "8000"]
