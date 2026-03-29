"""Integration tests for graph writer — NATS → AGE graph pipeline."""

from __future__ import annotations

import json

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


async def test_publish_and_merge_ip(pg_conn, nats_conn) -> None:
    """Publish a CanonicalIP entity to NATS and verify graph write."""
    js = nats_conn.jetstream()

    # Ensure stream exists
    from nats.js.api import StreamConfig

    await js.add_stream(
        StreamConfig(
            name="ENRICHED",
            subjects=["enriched.entity.>"],
            retention="work_queue",
            max_bytes=1_073_741_824,
        )
    )

    payload = {
        "label": "CanonicalIP",
        "properties": {
            "value": "198.51.100.99",
            "tlp": 1,
        },
    }
    await js.publish(
        "enriched.entity.ip",
        json.dumps(payload).encode(),
    )

    # Run graph_writer processing inline
    from ingest.graph_writer import _process_message

    sub = await js.subscribe("enriched.entity.>", durable="test_graph_write")
    msg = await sub.next_msg(timeout=5)
    await _process_message(pg_conn, msg)

    # Verify vertex exists in AGE
    cursor = await pg_conn.execute(
        """
        select * from ag_catalog.cypher('core_graph', $$
            match (v:CanonicalIP {value: '198.51.100.99'})
            return v
        $$) as (v agtype)
        """
    )
    row = await cursor.fetchone()
    assert row is not None, "CanonicalIP vertex should exist after graph write"


async def test_audit_log_entry_created(pg_conn, nats_conn) -> None:
    """Verify audit log entry after graph write."""
    cursor = await pg_conn.execute(
        """
        select * from audit_log
        where entity_label = 'CanonicalIP'
        and operation = 'MERGE'
        order by id desc
        limit 1
        """
    )
    row = await cursor.fetchone()
    assert row is not None, "Audit log entry should exist"
    assert row["actor"] == "graph_writer"


async def test_audit_log_hash_chain_intact(pg_conn) -> None:
    """Verify audit log hash chain integrity."""
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
