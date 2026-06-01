"""Tests for DLQ processor connection recovery (R-02).

The DLQ processor holds one long-lived PostgreSQL connection. These tests
drive ``ingest.dlq.processor.run`` with a fake NATS subscription and a fake
connection factory to assert that:

* a ``psycopg.OperationalError`` from message processing triggers a reconnect
  and the in-flight delivery is NAK-ed for redelivery; and
* a non-connection error rolls back and NAK-s **without** dropping the
  connection (no spurious reconnect).
"""

from __future__ import annotations

import psycopg
import pytest

from ingest.dlq import processor


class _FakeMsg:
    def __init__(self) -> None:
        self.data = b"{}"
        self.nak_count = 0
        self.ack_count = 0

    async def nak(self) -> None:
        self.nak_count += 1

    async def ack(self) -> None:
        self.ack_count += 1


class _FakeSub:
    def __init__(self, msgs: list[_FakeMsg]) -> None:
        self._msgs = msgs

    @property
    def messages(self):
        return self._aiter()

    async def _aiter(self):
        for m in self._msgs:
            yield m


class _FakeJS:
    def __init__(self, sub: _FakeSub) -> None:
        self._sub = sub

    async def subscribe(self, *_a, **_k) -> _FakeSub:
        return self._sub


class _FakeNC:
    def __init__(self, js: _FakeJS) -> None:
        self._js = js
        self.closed = False

    def jetstream(self) -> _FakeJS:
        return self._js

    async def close(self) -> None:
        self.closed = True


class _FakeConn:
    def __init__(self) -> None:
        self.closed = False
        self.rollback_count = 0

    async def close(self) -> None:
        self.closed = True

    async def rollback(self) -> None:
        self.rollback_count += 1


def _wire(monkeypatch: pytest.MonkeyPatch, msgs: list[_FakeMsg]) -> _FakeNC:
    sub = _FakeSub(msgs)
    js = _FakeJS(sub)
    nc = _FakeNC(js)

    async def fake_connect(_url: str) -> _FakeNC:
        return nc

    async def fake_ensure(_js) -> None:
        return None

    monkeypatch.setattr(processor.nats, "connect", fake_connect)
    monkeypatch.setattr(processor, "ensure_dlq_stream", fake_ensure)
    return nc


@pytest.mark.asyncio
async def test_reconnects_after_operational_error(monkeypatch: pytest.MonkeyPatch) -> None:
    msgs = [_FakeMsg(), _FakeMsg()]
    nc = _wire(monkeypatch, msgs)

    opened: list[_FakeConn] = []

    async def fake_open(_dsn: str) -> _FakeConn:
        conn = _FakeConn()
        opened.append(conn)
        return conn

    monkeypatch.setattr(processor, "_open_connection", fake_open)

    processed_on: list[_FakeConn] = []

    async def fake_process(conn, _js, _msg) -> None:
        processed_on.append(conn)
        if len(processed_on) == 1:
            raise psycopg.OperationalError("server closed the connection unexpectedly")

    monkeypatch.setattr(processor, "_process_dlq_message", fake_process)

    await processor.run(pg_dsn="dsn", nats_url="url")

    # Initial connection plus exactly one reconnect after the OperationalError.
    assert len(opened) == 2
    # The broken connection was closed during recovery.
    assert opened[0].closed is True
    # The first delivery was NAK-ed for redelivery; the second ran on conn #2.
    assert msgs[0].nak_count == 1
    assert processed_on[1] is opened[1]
    assert nc.closed is True


@pytest.mark.asyncio
async def test_generic_error_rolls_back_without_reconnect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    msgs = [_FakeMsg()]
    _wire(monkeypatch, msgs)

    opened: list[_FakeConn] = []

    async def fake_open(_dsn: str) -> _FakeConn:
        conn = _FakeConn()
        opened.append(conn)
        return conn

    monkeypatch.setattr(processor, "_open_connection", fake_open)

    async def fake_process(_conn, _js, _msg) -> None:
        raise ValueError("schema validation failed")

    monkeypatch.setattr(processor, "_process_dlq_message", fake_process)

    await processor.run(pg_dsn="dsn", nats_url="url")

    # No reconnect for a non-connection error: only the initial connection.
    assert len(opened) == 1
    assert opened[0].rollback_count == 1
    assert msgs[0].nak_count == 1
