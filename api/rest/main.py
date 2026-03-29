"""api.rest.main — FastAPI application for core-graph REST API."""

from __future__ import annotations

import logging
import os

import psycopg
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.config import NATS_URL, PG_DSN
from api.rest.middleware.logging import RequestLoggingMiddleware
from api.rest.middleware.request_id import RequestIDMiddleware
from api.rest.routes.entities import router as entities_router
from api.rest.routes.events import router as events_router
from api.rest.routes.query import router as query_router
from api.rest.routes.search import router as search_router

logger = logging.getLogger(__name__)

app = FastAPI(
    title="core-graph",
    description="Converged graph-vector knowledge platform REST API",
    version="0.1.0",
)

# -- Middleware (order matters: outermost first) --------------------------------

# CORS
cors_origins = os.environ.get("CG_CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request logging (after request ID so it can access the ID)
app.add_middleware(RequestLoggingMiddleware)

# Request ID injection (innermost — runs first)
app.add_middleware(RequestIDMiddleware)


# -- Health checks --------------------------------------------------------------


@app.get("/healthz")
async def healthz() -> dict:
    """Liveness probe."""
    return {"status": "ok"}


@app.get("/readyz")
async def readyz() -> dict:
    """Readiness probe — checks PostgreSQL and NATS connectivity."""
    pg_ok = False
    nats_ok = False

    # Check PostgreSQL
    try:
        async with await psycopg.AsyncConnection.connect(PG_DSN) as conn:
            await conn.execute("select 1")
            pg_ok = True
    except Exception:
        logger.warning("readyz: PostgreSQL check failed", exc_info=True)

    # Check NATS
    try:
        import nats

        nc = await nats.connect(NATS_URL)
        await nc.close()
        nats_ok = True
    except Exception:
        logger.warning("readyz: NATS check failed", exc_info=True)

    status = "ok" if pg_ok and nats_ok else "degraded"
    result = {"status": status, "postgres": pg_ok, "nats": nats_ok}

    if not (pg_ok and nats_ok):
        from fastapi.responses import JSONResponse

        return JSONResponse(content=result, status_code=503)

    return result


# -- API routes -----------------------------------------------------------------

app.include_router(entities_router, prefix="/api/v1")
app.include_router(search_router, prefix="/api/v1")
app.include_router(events_router, prefix="/api/v1")
app.include_router(query_router, prefix="/api/v1")
