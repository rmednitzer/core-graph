"""api.db — Shared async connection pool.

Provides a centralized psycopg connection pool for all MCP tools and
REST routes. Sets AGE search_path, RLS session variables, and a
role-derived statement_timeout on every connection acquired from the pool
so that authorization-related GUCs are enforced uniformly across REST,
MCP, ingest, and TAXII entry points.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from api import config
from api.utils.age_query_guard import query_timeout_ms

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
        config.PG_APP_DSN,
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
    await _log_enforcement_posture()


async def _log_enforcement_posture() -> None:
    """Report whether RLS is actually evaluated for the pool's role.

    Every policy in this repository is read through `app.max_tlp`, and none of
    them binds for a role that bypasses row-level security. A superuser or a
    BYPASSRLS role turns the whole TLP model into decoration, silently, with no
    error anywhere. `CG_PG_APP_DSN` falling back to `CG_PG_DSN` is the likely
    way to end up there by accident, so say so at startup rather than leaving
    an operator to infer it.

    Advisory only. It never blocks startup: refusing to serve because a GUC
    lookup failed would trade a security-posture warning for an outage.

    The except is deliberately broad. `_pool.open()` does not wait for a live
    connection, so this is the first code to actually need one, and it can fail
    with more than `psycopg.Error`: `psycopg_pool.PoolTimeout` is not a
    `psycopg.Error` subclass, and the local stack has a real window for it --
    initdb.sh sets cg_app's password after the migrations run, so an API
    container that starts in between gets an authentication failure the pool
    retries out of. Letting that escape would turn a diagnostic into a crash
    loop.
    """
    if _pool is None:
        return
    try:
        async with _pool.connection() as conn:
            row = await (
                await conn.execute(
                    "select current_user as role, "
                    "       rolsuper as is_superuser, "
                    "       rolbypassrls as bypasses_rls "
                    "  from pg_roles where rolname = current_user"
                )
            ).fetchone()
    except Exception as exc:  # noqa: BLE001 - diagnostic must not break startup
        logger.warning("Could not determine the pool role's RLS posture: %s", exc)
        return

    if row is None:
        return

    if row["is_superuser"] or row["bypasses_rls"]:
        logger.warning(
            "Connection pool is connected as %r, which bypasses row-level security "
            "(superuser=%s, bypassrls=%s). TLP policies are NOT enforced for "
            "requests. Point CG_PG_APP_DSN at the cg_app role from migration 038.",
            row["role"],
            row["is_superuser"],
            row["bypasses_rls"],
        )
    else:
        logger.info("Connection pool role %r is subject to row-level security", row["role"])


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
    """Acquire a connection from the pool with AGE, RLS, and timeout configured.

    Sets search_path for AGE, RLS session variables (`app.max_tlp`,
    `app.allowed_compartments`), and a role-derived `statement_timeout` from
    the caller identity. Yields the connection and returns it to the pool on
    exit.

    The statement_timeout is applied uniformly here so that *all* callers —
    REST, MCP tools, ingest workers, TAXII handlers — enforce the same per-role
    ceiling (no path can accidentally run unbounded queries).
    """
    if _pool is None:
        raise RuntimeError("Connection pool not initialised — call open_pool() first")

    async with _pool.connection() as conn:
        try:
            if pool_available is not None:
                pool_available.dec()

            await conn.execute("set search_path = ag_catalog, '$user', public")

            if caller_identity:
                max_tlp = str(caller_identity.get("max_tlp", config.DEFAULT_TLP))
                compartments = ",".join(caller_identity.get("allowed_compartments", []))
                await conn.execute("select set_config('app.max_tlp', %s, true)", (max_tlp,))
                await conn.execute(
                    "select set_config('app.allowed_compartments', %s, true)",
                    (compartments,),
                )

            timeout_ms = query_timeout_ms(caller_identity)
            await conn.execute(
                "select set_config('statement_timeout', %s, true)",
                (f"{timeout_ms}ms",),
            )

            yield conn
        finally:
            try:
                await conn.execute("select set_config('app.max_tlp', '', false)")
                await conn.execute("select set_config('app.allowed_compartments', '', false)")
                await conn.execute("select set_config('statement_timeout', '0', false)")
            except psycopg.Error:
                logger.debug("Could not reset session GUCs (connection in error state)")
            if pool_available is not None:
                pool_available.inc()
