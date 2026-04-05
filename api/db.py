"""api.db — Shared async connection pool.

Provides a centralized psycopg connection pool for all MCP tools and
REST routes. Sets AGE search_path and RLS session variables on every
connection acquired from the pool.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from api import config

logger = logging.getLogger(__name__)

try:
    from prometheus_client import Gauge

    pool_size: Gauge | None = Gauge("cg_pool_size", "Connection pool total size")
    pool_available: Gauge | None = Gauge("cg_pool_available", "Available connections in pool")
except ImportError:
    pool_size = None
    pool_available = None

_pool: AsyncConnectionPool | None = None


async def open_pool() -> None:
    """Create and open the shared connection pool (call on app startup)."""
    global _pool
    if _pool is not None:
        return
    _pool = AsyncConnectionPool(
        config.PG_DSN,
        min_size=config.PG_POOL_MIN,
        max_size=config.PG_POOL_MAX,
        kwargs={"row_factory": dict_row},
    )
    await _pool.open()
    if pool_size is not None:
        pool_size.set(_pool.max_size)
    if pool_available is not None:
        pool_available.set(_pool.max_size)
    logger.info(
        "Connection pool opened (min=%d, max=%d)",
        config.PG_POOL_MIN,
        config.PG_POOL_MAX,
    )


async def close_pool() -> None:
    """Close the shared connection pool (call on app shutdown)."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("Connection pool closed")


@asynccontextmanager
async def get_connection(
    caller_identity: dict[str, Any] | None = None,
) -> AsyncIterator:
    """Acquire a connection from the pool with AGE and RLS configured.

    Sets search_path for AGE and RLS session variables from the caller
    identity. Yields the connection and returns it to the pool on exit.
    """
    if _pool is None:
        raise RuntimeError("Connection pool not initialised — call open_pool() first")

    async with _pool.connection() as conn:
        if pool_available is not None:
            pool_available.dec()

        # Set AGE search path
        await conn.execute("set search_path = ag_catalog, '$user', public")

        # Set RLS session variables
        if caller_identity:
            max_tlp = str(caller_identity.get("max_tlp", config.DEFAULT_TLP))
            compartments = ",".join(caller_identity.get("allowed_compartments", []))
            await conn.execute("select set_config('app.max_tlp', %s, true)", (max_tlp,))
            await conn.execute(
                "select set_config('app.allowed_compartments', %s, true)",
                (compartments,),
            )

        try:
            yield conn
        finally:
            # Clear RLS session variables to prevent leakage across pool reuse.
            # Wrapped in try/except because the connection may be in an error
            # state if the caller's code raised an exception.
            try:
                await conn.execute("select set_config('app.max_tlp', '', false)")
                await conn.execute("select set_config('app.allowed_compartments', '', false)")
            except Exception:
                logger.debug("Could not reset RLS session variables (connection in error state)")
            if pool_available is not None:
                pool_available.inc()
