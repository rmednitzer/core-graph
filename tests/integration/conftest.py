"""Integration test fixtures — require a running stack.

The suite drives the real NATS→AGE ingest path: tests publish enriched
entities/relationships to the canonical JetStream streams (``ingest.streams``)
and an in-process ``graph_writer.run()`` consumes them and writes to the graph,
exactly as the deployed writer does. Tests then poll the graph for the result.

Requires PostgreSQL+AGE, NATS (JetStream), and Valkey; the REST tests also
need SpiceDB/Cerbos/MinIO for the readiness probe. Everything is skipped when
the stack is not reachable.
"""

from __future__ import annotations

import asyncio
import contextlib

import psycopg
import pytest
import pytest_asyncio
from psycopg.rows import dict_row

from api.config import NATS_URL, PG_DSN, VALKEY_URL
from ingest import graph_writer as _graph_writer
from ingest.streams import (
    DLQ_STREAM,
    ENRICHED_STREAM,
    INGEST_STREAM,
    ensure_dlq_stream,
    ensure_enriched_stream,
    ensure_ingest_stream,
)


def _stack_is_running() -> bool:
    """Check if the stack is available."""
    try:
        with psycopg.connect(PG_DSN) as conn:
            conn.execute("select 1")
        return True
    except Exception:
        return False


# Skip all integration tests if the stack is not running.
pytestmark = pytest.mark.integration

if not _stack_is_running():
    pytest.skip("Docker stack not running", allow_module_level=True)


@pytest_asyncio.fixture(autouse=True)
async def _reset_state():
    """Per-test reset of the shared messaging + pool state.

    Opens the api.db pool (REST routes and the ingest_event tool acquire from
    it; the httpx ASGITransport used by the REST tests does not run the app
    lifespan), provisions the canonical streams, purges them, and clears the
    writer dedup ledger so a re-used fixture payload is not acked as a duplicate
    (the dedup key is derived from message content, so identical payloads across
    tests would otherwise collide).
    """
    import nats

    from api.db import close_pool, open_pool

    await open_pool()

    async with await psycopg.AsyncConnection.connect(PG_DSN) as conn:
        with contextlib.suppress(Exception):
            await conn.execute("truncate table public.processed_messages")
            await conn.commit()

    nc = await nats.connect(NATS_URL)
    js = nc.jetstream()
    await ensure_enriched_stream(js)
    await ensure_ingest_stream(js)
    await ensure_dlq_stream(js)
    for name in (ENRICHED_STREAM, INGEST_STREAM, DLQ_STREAM):
        with contextlib.suppress(Exception):
            await js.purge_stream(name)
    await nc.close()

    yield

    # Close the lazily-opened shared NATS connection on the test's own loop;
    # pytest-asyncio gives every test a fresh loop, and an asyncio connection
    # must not outlive the loop it was created on.
    from api.nats_client import close_nats

    await close_nats()
    await close_pool()


@pytest_asyncio.fixture
async def nats_js():
    """A JetStream context bound to the canonical (already-provisioned) streams."""
    import nats

    nc = await nats.connect(NATS_URL)
    js = nc.jetstream()
    yield js
    await nc.close()


# Back-compat alias: a few tests want the raw connection to build a JetStream
# context themselves. Both resolve to the same canonical streams.
@pytest_asyncio.fixture
async def nats_conn():
    """Provide a NATS connection."""
    import nats

    nc = await nats.connect(NATS_URL)
    yield nc
    await nc.close()


@pytest_asyncio.fixture
async def graph_writer():
    """Run the real graph_writer.run() as a background task for the test.

    Consumes ``enriched.>`` and writes to the graph, so ingest tests exercise
    the same end-to-end NATS→AGE path as the deployed writer.
    """
    _graph_writer._READY_MARKER.unlink(missing_ok=True)
    task = asyncio.create_task(_graph_writer.run())
    # Wait until the subscription is live (run() touches the readiness marker).
    for _ in range(200):
        if _graph_writer._READY_MARKER.exists():
            break
        if task.done():  # startup failed — surface the exception
            await task
        await asyncio.sleep(0.05)
    yield
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError, Exception):
        await task
    _graph_writer._READY_MARKER.unlink(missing_ok=True)


@pytest_asyncio.fixture
async def enrichment_worker():
    """Run the real enrichment_worker.run() as a background task for the test.

    Consumes ``ingest.>`` and republishes canonical envelopes onto
    ``enriched.entity.>``, so raw-STIX tests exercise the same two-stage
    NATS path (enrichment → writer) as the deployed pipeline.
    """
    from ingest import enrichment_worker as _enrichment_worker

    _enrichment_worker._READY_MARKER.unlink(missing_ok=True)
    task = asyncio.create_task(_enrichment_worker.run())
    for _ in range(200):
        if _enrichment_worker._READY_MARKER.exists():
            break
        if task.done():  # startup failed — surface the exception
            await task
        await asyncio.sleep(0.05)
    yield
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError, Exception):
        await task
    _enrichment_worker._READY_MARKER.unlink(missing_ok=True)


@pytest_asyncio.fixture
async def pg_conn():
    """Autocommit AGE connection for reads/polls and superuser graph writes.

    Autocommit so each statement reads a fresh snapshot — required for polling
    the in-process writer's committed writes. RLS-sensitive reads switch to a
    non-superuser role explicitly (a superuser bypasses RLS).
    """
    conn = await psycopg.AsyncConnection.connect(PG_DSN, row_factory=dict_row, autocommit=True)
    await conn.execute("set search_path = ag_catalog, '$user', public")
    await conn.execute("select set_config('app.max_tlp', '4', false)")
    yield conn
    await conn.close()


@pytest_asyncio.fixture
async def valkey_conn():
    """Provide a Valkey (Redis) connection."""
    import redis.asyncio as aioredis

    r = aioredis.from_url(VALKEY_URL)
    yield r
    await r.aclose()
