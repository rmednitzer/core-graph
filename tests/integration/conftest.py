"""Integration test fixtures — require running Docker stack."""

from __future__ import annotations

import asyncio

import psycopg
import pytest
import pytest_asyncio
from psycopg.rows import dict_row

from api.config import NATS_URL, PG_DSN, VALKEY_URL


def _stack_is_running() -> bool:
    """Check if the Docker stack is available."""
    try:
        with psycopg.connect(PG_DSN) as conn:
            conn.execute("select 1")
        return True
    except Exception:
        return False


# Skip all integration tests if the stack is not running
pytestmark = pytest.mark.integration

if not _stack_is_running():
    pytest.skip("Docker stack not running", allow_module_level=True)


@pytest.fixture(scope="session")
def event_loop():
    """Create a session-scoped event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def pg_conn():
    """Provide an async PostgreSQL connection with AGE search path."""
    conn = await psycopg.AsyncConnection.connect(PG_DSN, row_factory=dict_row)
    await conn.execute("set search_path = ag_catalog, '$user', public")
    await conn.execute("select set_config('app.max_tlp', '4', true)")
    yield conn
    await conn.close()


@pytest_asyncio.fixture
async def nats_conn():
    """Provide a NATS connection."""
    import nats

    nc = await nats.connect(NATS_URL)
    yield nc
    await nc.close()


@pytest_asyncio.fixture
async def valkey_conn():
    """Provide a Valkey (Redis) connection."""
    import redis.asyncio as aioredis

    r = aioredis.from_url(VALKEY_URL)
    yield r
    await r.aclose()
