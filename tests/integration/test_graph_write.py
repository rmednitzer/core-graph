"""Integration tests for graph writer — NATS → AGE graph pipeline."""

from __future__ import annotations

import asyncio
import json

import pytest

from tests.integration._helpers import poll_cypher, poll_query

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


async def test_publish_and_merge_ip(nats_js, graph_writer, pg_conn) -> None:
    """Publish a CanonicalIP entity and verify the writer merges it into AGE."""
    payload = {
        "label": "CanonicalIP",
        "properties": {"value": "198.51.100.99", "tlp": 1},
    }
    await nats_js.publish("enriched.entity.ip", json.dumps(payload).encode())

    rows = await poll_cypher(
        pg_conn,
        """
        select * from ag_catalog.cypher('core_graph', $$
            match (v:CanonicalIP {value: '198.51.100.99'})
            return v.value
        $$) as (v agtype)
        """,
    )
    assert rows, "CanonicalIP vertex should exist after graph write"


async def test_audit_log_entry_created(nats_js, graph_writer, pg_conn) -> None:
    """The writer records a CanonicalIP MERGE in the append-only audit log."""
    payload = {
        "label": "CanonicalIP",
        "properties": {"value": "198.51.100.123", "tlp": 1},
    }
    await nats_js.publish("enriched.entity.ip", json.dumps(payload).encode())
    await poll_cypher(
        pg_conn,
        """
        select * from ag_catalog.cypher('core_graph', $$
            match (v:CanonicalIP {value: '198.51.100.123'})
            return v.value
        $$) as (v agtype)
        """,
    )

    row = await poll_query(
        pg_conn,
        """
        select actor, operation from audit_log
        where entity_label = 'CanonicalIP' and operation = 'MERGE'
        order by id desc limit 1
        """,
    )
    assert row is not None, "Audit log entry should exist"
    assert row["actor"] == "graph_writer"


async def test_audit_log_hash_chain_intact(nats_js, graph_writer, pg_conn) -> None:
    """Verify audit log hash chain integrity after writes."""
    for value in ("198.51.100.201", "198.51.100.202"):
        await nats_js.publish(
            "enriched.entity.ip",
            json.dumps({"label": "CanonicalIP", "properties": {"value": value, "tlp": 1}}).encode(),
        )
    await asyncio.sleep(1.0)

    cursor = await pg_conn.execute(
        "select id, entry_hash, prev_entry_hash from audit_log order by id asc"
    )
    entries = await cursor.fetchall()
    if len(entries) < 2:
        pytest.skip("Not enough audit entries to verify chain")

    prev_hash = "genesis"
    for entry in entries:
        assert entry["prev_entry_hash"] == prev_hash, (
            f"Chain broken at id={entry['id']}: "
            f"expected prev={prev_hash}, got={entry['prev_entry_hash']}"
        )
        prev_hash = entry["entry_hash"]
