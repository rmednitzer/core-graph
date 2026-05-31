"""Unit tests for the graph writer's at-least-once dedup key derivation.

The transactional claim itself needs a live Postgres + JetStream and is covered
by the integration suite; here we pin the pure key-derivation logic that decides
whether a redelivery can be recognised at all.
"""

from __future__ import annotations

from ingest.streams import content_msg_id


def test_content_msg_id_is_prefixed_sha256() -> None:
    key = content_msg_id({"label": "Malware", "properties": {"stix_id": "malware--1"}})
    assert key.startswith("sha256:")
    assert len(key) == len("sha256:") + 64  # hex digest


def test_content_msg_id_is_stable_for_identical_payloads() -> None:
    # Same content -> same key, so a redelivery (or exact duplicate) of a stored
    # message is recognised regardless of how many times it is delivered.
    a = content_msg_id({"label": "Malware", "properties": {"stix_id": "malware--1"}})
    b = content_msg_id({"label": "Malware", "properties": {"stix_id": "malware--1"}})
    assert a == b


def test_content_msg_id_is_key_order_independent() -> None:
    # Canonical (sorted-key) JSON: dict insertion order must not change the key.
    assert content_msg_id({"a": 1, "b": 2}) == content_msg_id({"b": 2, "a": 1})


def test_content_msg_id_changes_with_stix_version() -> None:
    # A new STIX `modified` changes the payload and thus the key, so an updated
    # object is reprocessed (not suppressed as a duplicate) and reaches the
    # writer's ON MATCH t_recorded refresh.
    v1 = content_msg_id({"id": "malware--1", "modified": "2026-01-01T00:00:00Z"})
    v2 = content_msg_id({"id": "malware--1", "modified": "2026-02-01T00:00:00Z"})
    assert v1 != v2


def test_content_msg_id_is_incarnation_independent() -> None:
    # The key is derived from content only, never a JetStream (stream, seq) pair,
    # so it is identical no matter which stream incarnation delivered it. This is
    # what prevents reused sequences (after a stream rebuild) from colliding with
    # surviving claims in the 90-day ledger and silently suppressing fresh data.
    payload = {"label": "ThreatActor", "properties": {"stix_id": "ta--1"}}
    assert content_msg_id(payload) == content_msg_id(dict(payload))


def test_content_msg_id_distinguishes_different_payloads() -> None:
    assert content_msg_id({"x": 1}) != content_msg_id({"x": 2})
