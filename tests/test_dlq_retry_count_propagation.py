"""Tests that a re-failed DLQ retry carries its counters forward.

``ingest.dlq.processor`` republishes a retried message to its
``original_subject`` with a ``_dlq_retry_count`` (and ``_dlq_first_failed``)
marker embedded in the payload. If that redelivery fails again,
``ingest.graph_writer`` and ``ingest.enrichment_worker`` build a fresh
``dlq.*`` envelope — and previously hardcoded ``retry_count`` to ``0`` there,
discarding the DLQ processor's own counter on every cycle. That meant
``CG_DLQ_MAX_RETRIES`` was never actually reached: a poison message looked
like a first-time failure forever and was retried indefinitely instead of
being archived to ``dlq_archive``.

These tests drive each worker's ``run()`` with a fake NATS/psycopg substrate
(mirroring ``tests/test_dlq_reconnect.py``) and assert the republished
``dlq.*`` envelope reflects the incoming ``_dlq_retry_count`` /
``_dlq_first_failed`` markers rather than resetting them.
"""

from __future__ import annotations

import json

import pytest

from ingest import enrichment_worker, graph_writer


class _FakeMsg:
    def __init__(self, data: bytes, subject: str = "enriched.entity.threatintel.misp") -> None:
        self.data = data
        self.subject = subject
        self.ack_count = 0

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
        self.published: list[tuple[str, bytes]] = []

    async def subscribe(self, *_a, **_k) -> _FakeSub:
        return self._sub

    async def publish(self, subject: str, data: bytes) -> None:
        self.published.append((subject, data))


class _FakeNC:
    def __init__(self, js: _FakeJS) -> None:
        self._js = js

    def jetstream(self) -> _FakeJS:
        return self._js

    async def close(self) -> None:
        pass


class _FakeConn:
    async def set_autocommit(self, _value: bool) -> None:
        pass

    async def execute(self, *_a, **_k) -> None:
        pass

    async def rollback(self) -> None:
        pass

    async def close(self) -> None:
        pass


@pytest.mark.asyncio
async def test_graph_writer_dlq_republish_carries_retry_count_forward(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # This message is itself a DLQ retry republish (it carries the markers
    # ingest.dlq.processor.run attaches), and processing it fails again.
    msg = _FakeMsg(
        json.dumps({"label": "Malware", "_dlq_retry_count": 2, "_dlq_first_failed": "t0"}).encode()
    )
    sub = _FakeSub([msg])
    js = _FakeJS(sub)
    nc = _FakeNC(js)

    async def fake_connect(_url: str):
        return nc

    async def fake_pg_connect(_dsn: str, **_kw):
        return _FakeConn()

    async def fake_ensure(_js) -> None:
        return None

    async def fake_process(_conn, _msg) -> None:
        raise ValueError("boom")

    monkeypatch.setattr(graph_writer.nats, "connect", fake_connect)
    monkeypatch.setattr(graph_writer.psycopg.AsyncConnection, "connect", fake_pg_connect)
    monkeypatch.setattr(graph_writer, "ensure_enriched_stream", fake_ensure)
    monkeypatch.setattr(graph_writer, "ensure_dlq_stream", fake_ensure)
    monkeypatch.setattr(graph_writer, "_process_message", fake_process)

    await graph_writer.run(pg_dsn="dsn", nats_url="url")

    assert len(js.published) == 1
    subject, data = js.published[0]
    assert subject == f"dlq.{msg.subject}"
    dlq_payload = json.loads(data.decode())
    # The DLQ processor's counter (2) is carried forward, not reset to 0.
    assert dlq_payload["retry_count"] == 2
    assert dlq_payload["first_failed"] == "t0"


@pytest.mark.asyncio
async def test_graph_writer_dlq_republish_defaults_for_first_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A first-time failure (no prior DLQ round trip) still starts at 0.
    msg = _FakeMsg(json.dumps({"label": "Malware"}).encode())
    sub = _FakeSub([msg])
    js = _FakeJS(sub)
    nc = _FakeNC(js)

    async def fake_connect(_url: str):
        return nc

    async def fake_pg_connect(_dsn: str, **_kw):
        return _FakeConn()

    async def fake_ensure(_js) -> None:
        return None

    async def fake_process(_conn, _msg) -> None:
        raise ValueError("boom")

    monkeypatch.setattr(graph_writer.nats, "connect", fake_connect)
    monkeypatch.setattr(graph_writer.psycopg.AsyncConnection, "connect", fake_pg_connect)
    monkeypatch.setattr(graph_writer, "ensure_enriched_stream", fake_ensure)
    monkeypatch.setattr(graph_writer, "ensure_dlq_stream", fake_ensure)
    monkeypatch.setattr(graph_writer, "_process_message", fake_process)

    await graph_writer.run(pg_dsn="dsn", nats_url="url")

    dlq_payload = json.loads(js.published[0][1].decode())
    assert dlq_payload["retry_count"] == 0


@pytest.mark.asyncio
async def test_enrichment_worker_dlq_republish_carries_retry_count_forward(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    msg = _FakeMsg(
        json.dumps({"foo": "bar", "_dlq_retry_count": 1, "_dlq_first_failed": "t0"}).encode(),
        subject="ingest.threatintel.misp",
    )
    sub = _FakeSub([msg])
    js = _FakeJS(sub)
    nc = _FakeNC(js)

    async def fake_connect(_url: str):
        return nc

    async def fake_ensure(_js) -> None:
        return None

    async def fake_process(_js, _msg) -> None:
        raise ValueError("boom")

    monkeypatch.setattr(enrichment_worker.nats, "connect", fake_connect)
    monkeypatch.setattr(enrichment_worker, "ensure_ingest_stream", fake_ensure)
    monkeypatch.setattr(enrichment_worker, "ensure_enriched_stream", fake_ensure)
    monkeypatch.setattr(enrichment_worker, "ensure_dlq_stream", fake_ensure)
    monkeypatch.setattr(enrichment_worker, "_process_message", fake_process)

    await enrichment_worker.run(nats_url="url")

    assert len(js.published) == 1
    subject, data = js.published[0]
    assert subject == f"dlq.{msg.subject}"
    dlq_payload = json.loads(data.decode())
    assert dlq_payload["retry_count"] == 1
    assert dlq_payload["first_failed"] == "t0"


@pytest.mark.asyncio
async def test_graph_writer_dlq_republish_tolerates_non_object_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A JSON payload that is not an object (so it cannot carry markers) must
    # still be published to the DLQ with first-failure defaults, not fail
    # inside the DLQ-publish handler and be acked away.
    msg = _FakeMsg(json.dumps(["not", "an", "object"]).encode())
    sub = _FakeSub([msg])
    js = _FakeJS(sub)
    nc = _FakeNC(js)

    async def fake_connect(_url: str):
        return nc

    async def fake_pg_connect(_dsn: str, **_kw):
        return _FakeConn()

    async def fake_ensure(_js) -> None:
        return None

    async def fake_process(_conn, _msg) -> None:
        raise ValueError("boom")

    monkeypatch.setattr(graph_writer.nats, "connect", fake_connect)
    monkeypatch.setattr(graph_writer.psycopg.AsyncConnection, "connect", fake_pg_connect)
    monkeypatch.setattr(graph_writer, "ensure_enriched_stream", fake_ensure)
    monkeypatch.setattr(graph_writer, "ensure_dlq_stream", fake_ensure)
    monkeypatch.setattr(graph_writer, "_process_message", fake_process)

    await graph_writer.run(pg_dsn="dsn", nats_url="url")

    assert len(js.published) == 1
    dlq_payload = json.loads(js.published[0][1].decode())
    assert dlq_payload["payload"] == ["not", "an", "object"]
    assert dlq_payload["retry_count"] == 0
