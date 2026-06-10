"""api.nats_client — Shared NATS JetStream connection.

ingest_event and the TAXII add-objects path used to open (and close) a fresh
NATS connection per request — the correctness concern (connect/publish
timeouts) was fixed in the modernization pass, but the per-request TCP+TLS
handshake remained as deferred roadmap item #7 of ADR-0007. This module is the
NATS analogue of ``api.db``: one process-wide connection, opened lazily on
first use, reused across requests, closed by the application lifespan.

nats-py reconnects automatically while the connection object is alive, so a
broker restart does not invalidate the cached connection; only a *closed*
connection (reconnect budget exhausted, or an explicit close) is replaced on
the next acquisition. Publish timeouts remain the caller's responsibility —
this module only owns connection lifecycle.

Asyncio primitives (the connection and its guard lock) are bound to the event
loop they were created on. Production processes run a single loop, but test
runners create one loop per test; reusing a connection across loops raises
"attached to a different loop". The cache is therefore keyed to the running
loop: acquiring from a new loop drops the stale reference (its loop is gone,
so it cannot be closed from here) and reconnects.
"""

from __future__ import annotations

import asyncio
import logging

import nats
from nats.js import JetStreamContext

from api.config import NATS_URL
from ingest.streams import ensure_ingest_stream

logger = logging.getLogger(__name__)

_nc: nats.NATS | None = None
_js: JetStreamContext | None = None
_loop: asyncio.AbstractEventLoop | None = None
_lock: asyncio.Lock | None = None


def _get_lock() -> asyncio.Lock:
    """Return the guard lock for the *running* loop, recreating on loop change."""
    global _lock, _loop, _nc, _js
    loop = asyncio.get_running_loop()
    if _lock is None or _loop is not loop:
        if _nc is not None:
            logger.warning("Event loop changed; dropping stale NATS connection reference")
        _nc, _js = None, None
        _lock = asyncio.Lock()
        _loop = loop
    return _lock


async def get_jetstream() -> JetStreamContext:
    """Return the shared JetStream context, connecting on first use.

    The INGEST stream is (idempotently) ensured once per connection, not per
    request. Raises whatever ``nats.connect`` raises when the broker is
    unreachable — callers keep their existing fail-closed handling.
    """
    global _nc, _js
    async with _get_lock():
        if _nc is None or _nc.is_closed:
            nc = await nats.connect(NATS_URL, connect_timeout=5)
            try:
                js = nc.jetstream()
                await ensure_ingest_stream(js)
            except Exception:
                await nc.close()
                raise
            _nc, _js = nc, js
            logger.info("Shared NATS connection opened (%s)", NATS_URL)
        elif not _nc.is_connected:
            # Mid-reconnect. A JetStream publish against a reconnecting
            # connection would silently wait out its full per-publish timeout
            # (10 s × N objects on the TAXII bundle path); the per-request
            # connections this module replaced failed within connect_timeout=5
            # instead. Restore that failure mode: give the client one
            # 5-second window to come back (flush resolves as soon as the
            # reconnect completes), else surface broker-down to the caller's
            # existing fail-closed handling.
            await _nc.flush(timeout=5)
        assert _js is not None
        return _js


async def close_nats() -> None:
    """Close the shared connection (call on app shutdown).

    Never raises: shutdown callers run further teardown (e.g. the DB pool)
    after this, so a broker that vanished mid-drain must not abort the rest
    of the shutdown sequence. State is always reset.
    """
    global _nc, _js
    async with _get_lock():
        try:
            if _nc is not None and not _nc.is_closed:
                try:
                    await _nc.drain()
                except Exception:
                    logger.warning("NATS drain failed; closing hard", exc_info=True)
                    try:
                        await _nc.close()
                    except Exception:
                        logger.warning("NATS close failed; dropping connection", exc_info=True)
        finally:
            _nc, _js = None, None
            logger.info("Shared NATS connection closed")
