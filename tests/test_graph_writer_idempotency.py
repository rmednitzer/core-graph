"""Unit tests for the graph writer's at-least-once dedup key derivation.

The transactional claim itself needs a live Postgres + JetStream and is covered
by the integration suite; here we pin the pure key-derivation logic that decides
whether a redelivery can be recognised at all.
"""

from __future__ import annotations

from ingest.graph_writer import _delivery_key


class _Seq:
    def __init__(self, stream: int) -> None:
        self.stream = stream


class _Meta:
    def __init__(self, stream: str, seq: int) -> None:
        self.stream = stream
        self.sequence = _Seq(seq)


class _Msg:
    def __init__(self, meta: _Meta | None) -> None:
        self._meta = meta

    @property
    def metadata(self) -> _Meta:
        if self._meta is None:
            raise ValueError("not a JetStream message")
        return self._meta


def test_delivery_key_from_jetstream_metadata() -> None:
    assert _delivery_key(_Msg(_Meta("ENRICHED", 42))) == "ENRICHED:42"


def test_delivery_key_is_stable_across_redeliveries() -> None:
    # Same stored message (same stream + stream sequence) -> same key, so a
    # redelivery is recognised regardless of how many times it is delivered.
    a = _delivery_key(_Msg(_Meta("ENRICHED", 7)))
    b = _delivery_key(_Msg(_Meta("ENRICHED", 7)))
    assert a == b


def test_delivery_key_none_when_metadata_unavailable() -> None:
    # A non-JetStream message yields no key; dedup is skipped, not fatal.
    assert _delivery_key(_Msg(None)) is None
