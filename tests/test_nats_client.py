"""Unit tests for api.nats_client — the shared NATS connection (ADR-0007 #7).

Pins the lifecycle the request paths rely on: one connect across many
acquisitions, stream provisioning once per connection, reconnect only after
the connection is closed, and a failed connect leaving no cached broken state.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from api import nats_client


@pytest.fixture(autouse=True)
def _reset_module_state():
    """Each test starts with no cached connection."""
    nats_client._nc = None
    nats_client._js = None
    nats_client._loop = None
    nats_client._lock = None
    yield
    nats_client._nc = None
    nats_client._js = None
    nats_client._loop = None
    nats_client._lock = None


def _fake_connection() -> tuple[MagicMock, AsyncMock]:
    nc = MagicMock()
    nc.is_closed = False
    nc.jetstream = MagicMock(return_value=AsyncMock())
    nc.close = AsyncMock()
    nc.drain = AsyncMock()
    return nc, nc.jetstream.return_value


@pytest.mark.asyncio
async def test_connection_is_reused_across_acquisitions(monkeypatch) -> None:
    nc, js = _fake_connection()
    connect = AsyncMock(return_value=nc)
    monkeypatch.setattr(nats_client.nats, "connect", connect)
    ensure = AsyncMock()
    monkeypatch.setattr(nats_client, "ensure_ingest_stream", ensure)

    first = await nats_client.get_jetstream()
    second = await nats_client.get_jetstream()

    assert first is js and second is js
    connect.assert_awaited_once()
    ensure.assert_awaited_once_with(js)  # stream ensured per connection, not per request


@pytest.mark.asyncio
async def test_closed_connection_is_replaced(monkeypatch) -> None:
    nc1, js1 = _fake_connection()
    nc2, js2 = _fake_connection()
    connect = AsyncMock(side_effect=[nc1, nc2])
    monkeypatch.setattr(nats_client.nats, "connect", connect)
    monkeypatch.setattr(nats_client, "ensure_ingest_stream", AsyncMock())

    assert await nats_client.get_jetstream() is js1
    nc1.is_closed = True  # reconnect budget exhausted / broker closed us

    assert await nats_client.get_jetstream() is js2
    assert connect.await_count == 2


@pytest.mark.asyncio
async def test_failed_stream_provisioning_does_not_cache_connection(monkeypatch) -> None:
    nc, _ = _fake_connection()
    monkeypatch.setattr(nats_client.nats, "connect", AsyncMock(return_value=nc))
    monkeypatch.setattr(
        nats_client, "ensure_ingest_stream", AsyncMock(side_effect=RuntimeError("no js"))
    )

    with pytest.raises(RuntimeError):
        await nats_client.get_jetstream()

    nc.close.assert_awaited_once()
    assert nats_client._nc is None, "a broken connection must not be cached"


@pytest.mark.asyncio
async def test_close_nats_drains_and_resets(monkeypatch) -> None:
    nc, _ = _fake_connection()
    monkeypatch.setattr(nats_client.nats, "connect", AsyncMock(return_value=nc))
    monkeypatch.setattr(nats_client, "ensure_ingest_stream", AsyncMock())

    await nats_client.get_jetstream()
    await nats_client.close_nats()

    nc.drain.assert_awaited_once()
    assert nats_client._nc is None and nats_client._js is None


@pytest.mark.asyncio
async def test_close_nats_without_open_connection_is_a_noop() -> None:
    await nats_client.close_nats()  # must not raise
