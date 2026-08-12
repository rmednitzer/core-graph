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
from api.utils.clearance_roles import DATABASE_ROLES, database_role_for

logger = logging.getLogger(__name__)

try:
    from prometheus_client import Gauge

    pool_size: Gauge | None = Gauge("cg_pool_size", "Connection pool total size")
    pool_available: Gauge | None = Gauge("cg_pool_available", "Available connections in pool")
except ImportError:
    pool_size = None
    pool_available = None

_pool: AsyncConnectionPool | None = None


async def _reset_connection(conn: Any) -> None:
    """Scrub per-request state before a connection re-enters the pool.

    The last line of defence for the clearance role `get_connection` assumes.
    `SET LOCAL ROLE` already reverts at transaction end and `get_connection`
    already issues `RESET ROLE` in its finally, so by the time this runs the
    role should be `cg_app` twice over. It runs anyway because the failure it
    guards is the one that matters: a connection returned to the pool still
    wearing a clearance would hand that clearance to whoever borrows it next,
    silently and with no error anywhere.

    psycopg_pool discards a connection whose reset raises, which is the right
    outcome here -- losing a connection is cheaper than reusing a dirty one.
    """
    await conn.execute("reset role")
    await conn.execute("reset all")


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
        reset=_reset_connection,
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
    # Typed Any deliberately. The pool is constructed with `row_factory=dict_row`
    # a few lines up, so the runtime value is a mapping, but `execute()` is
    # annotated as returning the default `tuple[Any, ...]` and mypy has no way to
    # see the pool's factory from here. Positional access would type-check and be
    # wrong: unpacking a dict yields its keys, so `row[0]` would silently become
    # the string "role" rather than the role name.
    row: Any
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

    It also assumes the caller's clearance role for the duration, when one maps
    (ADR-0015). That is what makes the role-targeted policies — `ciso_full_access`
    and its write twin — apply, and what puts the clearance role's own table
    grants between a request and the data, so enforcement no longer rests on the
    `app.max_tlp` GUC alone. A caller outside the seven-role hierarchy keeps the
    pool's own `cg_app`, which is still non-superuser and still policy-bound.
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

            # Last, so everything above runs as cg_app. The clearance roles hold
            # no privilege this function needs, and setting the role first would
            # make the GUC writes depend on grants they do not need to depend on.
            db_role = database_role_for(caller_identity)
            if db_role is not None:
                # SET LOCAL, not SET. The role then reverts when the transaction
                # ends, which the pool's context manager does on the way out —
                # so a connection cannot be handed to the next borrower still
                # wearing a clearance it was not given. The RESET ROLE below and
                # the pool's reset hook are the second and third lines of that
                # defence, not the first.
                #
                # Interpolated rather than bound because a role name cannot be a
                # parameter. Safe only because db_role came out of the
                # CLEARANCE_ROLES allowlist; the assertion says so out loud
                # rather than trusting the reader to check the call site.
                if db_role not in DATABASE_ROLES:  # pragma: no cover - defensive
                    raise RuntimeError(f"refusing to SET ROLE to unlisted role {db_role!r}")
                await conn.execute(f"set local role {db_role}")

            yield conn
        finally:
            try:
                # Before the GUC resets, which are session-level writes: run
                # them as the pool's own role rather than as a clearance role
                # that may not outlive this block.
                await conn.execute("reset role")
                await conn.execute("select set_config('app.max_tlp', '', false)")
                await conn.execute("select set_config('app.allowed_compartments', '', false)")
                await conn.execute("select set_config('statement_timeout', '0', false)")
            except psycopg.Error:
                logger.debug("Could not reset session GUCs (connection in error state)")
            if pool_available is not None:
                pool_available.inc()
