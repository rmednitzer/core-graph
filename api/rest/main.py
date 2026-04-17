"""api.rest.main — FastAPI application for core-graph REST API."""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import nats
import psycopg
import redis.asyncio as aioredis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from minio import Minio

from api.config import (
    MINIO_ACCESS_KEY,
    MINIO_ENDPOINT,
    MINIO_EVIDENCE_BUCKET,
    MINIO_SECRET_KEY,
    MINIO_USE_SSL,
    NATS_URL,
    PG_DSN,
    VALKEY_URL,
)
from api.db import close_pool, open_pool
from api.rest.middleware.logging import RequestLoggingMiddleware
from api.rest.middleware.metrics import MetricsMiddleware, metrics_endpoint
from api.rest.middleware.oidc import OIDCMiddleware
from api.rest.middleware.request_id import RequestIDMiddleware
from api.rest.routes.entities import router as entities_router
from api.rest.routes.events import router as events_router
from api.rest.routes.query import router as query_router
from api.rest.routes.search import router as search_router
from api.taxii.server import taxii_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Open connection pool on startup, close on shutdown."""
    await open_pool()
    yield
    await close_pool()


app = FastAPI(
    title="core-graph",
    description="Converged graph-vector knowledge platform REST API",
    version="0.1.0",
    lifespan=lifespan,
)

# -- Middleware (order matters: outermost first) --------------------------------

# CORS — default is "*" for local development only. Production MUST set
# CG_CORS_ORIGINS to an explicit allow-list; wildcards combined with
# credentialed requests are a well-known browser footgun.
cors_origins = [o.strip() for o in os.environ.get("CG_CORS_ORIGINS", "*").split(",") if o.strip()]
if "*" in cors_origins and os.environ.get("CG_OIDC_ENABLED", "false").lower() == "true":
    logger.warning(
        "CG_CORS_ORIGINS contains '*' while OIDC is enabled; set an explicit origin list."
    )
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Prometheus metrics (outermost after CORS)
app.add_middleware(MetricsMiddleware)

# Request logging (after request ID so it can access the ID)
app.add_middleware(RequestLoggingMiddleware)

# OIDC authentication (after logging, before routes)
app.add_middleware(OIDCMiddleware)

# Request ID injection (innermost — runs first)
app.add_middleware(RequestIDMiddleware)


# -- Health checks --------------------------------------------------------------


@app.get("/healthz")
async def healthz() -> dict:
    """Liveness probe."""
    return {"status": "ok"}


@app.get("/readyz")
async def readyz() -> dict:
    """Readiness probe — checks PostgreSQL, NATS, Valkey, and MinIO connectivity."""
    pg_ok = False
    nats_ok = False
    valkey_ok = False
    minio_ok = False

    # Check PostgreSQL
    try:
        async with await psycopg.AsyncConnection.connect(PG_DSN) as conn:
            await conn.execute("select 1")
            pg_ok = True
    except Exception:
        logger.warning("readyz: PostgreSQL check failed", exc_info=True)

    # Check NATS
    try:
        nc = await nats.connect(NATS_URL)
        await nc.close()
        nats_ok = True
    except Exception:
        logger.warning("readyz: NATS check failed", exc_info=True)

    # Check Valkey
    try:
        r = aioredis.from_url(VALKEY_URL)
        await r.ping()
        await r.aclose()
        valkey_ok = True
    except Exception:
        logger.warning("readyz: Valkey check failed", exc_info=True)

    # Check MinIO
    try:
        mc = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=MINIO_USE_SSL,
        )
        mc.bucket_exists(MINIO_EVIDENCE_BUCKET)
        minio_ok = True
    except Exception:
        logger.warning("readyz: MinIO check failed", exc_info=True)

    all_ok = pg_ok and nats_ok and valkey_ok and minio_ok
    status = "ok" if all_ok else "degraded"
    result = {
        "status": status,
        "postgres": pg_ok,
        "nats": nats_ok,
        "valkey": valkey_ok,
        "minio": minio_ok,
    }

    if not all_ok:
        return JSONResponse(content=result, status_code=503)

    return result


# -- Metrics endpoint -----------------------------------------------------------

app.add_api_route("/metrics", metrics_endpoint, methods=["GET"], include_in_schema=False)

# -- API routes -----------------------------------------------------------------

app.include_router(entities_router, prefix="/api/v1")
app.include_router(search_router, prefix="/api/v1")
app.include_router(events_router, prefix="/api/v1")
app.include_router(query_router, prefix="/api/v1")
app.include_router(taxii_router, prefix="/taxii2")
