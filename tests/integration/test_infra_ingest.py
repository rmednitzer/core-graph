"""Integration tests for Layer 7 infrastructure entity ingest pipeline."""

from __future__ import annotations

import json

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


async def test_publish_and_merge_host(pg_conn, nats_conn) -> None:
    """Publish a Host entity to NATS and verify graph write."""
    js = nats_conn.jetstream()

    from nats.js.api import StreamConfig

    await js.add_stream(
        StreamConfig(
            name="ENRICHED",
            subjects=["enriched.entity.>"],
            retention="work_queue",
            max_bytes=1_073_741_824,
        )
    )

    from ingest.canonical import canonical_key

    payload = {
        "label": "Host",
        "properties": {
            "canonical_key": canonical_key("host", "netbox-42"),
            "name": "axiom",
            "host_type": "device",
            "platform": "ubuntu-24.04",
            "status": "active",
            "site": "homelab",
            "tlp": 1,
        },
    }
    await js.publish("enriched.entity.host", json.dumps(payload).encode())

    from ingest.graph_writer import _process_message

    sub = await js.subscribe("enriched.entity.>", durable="test_infra_host")
    msg = await sub.next_msg(timeout=5)
    await _process_message(pg_conn, msg)

    cursor = await pg_conn.execute(
        """
        select * from ag_catalog.cypher('core_graph', $$
            match (v:Host {name: 'axiom'})
            return v.name, v.host_type, v.status
        $$) as (name agtype, host_type agtype, status agtype)
        """
    )
    row = await cursor.fetchone()
    assert row is not None
    assert "axiom" in str(row["name"])


async def test_publish_and_merge_monitoring_alert(pg_conn, nats_conn) -> None:
    """Publish a MonitoringAlert entity to NATS and verify graph write."""
    js = nats_conn.jetstream()

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
        "label": "MonitoringAlert",
        "properties": {
            "fingerprint": "testfp001",
            "alertname": "HighCPUUsage",
            "severity": "critical",
            "status": "firing",
            "instance": "10.0.0.5:9100",
            "tlp": 1,
            "starts_at": "2026-03-29T12:00:00Z",
            "ends_at": None,
        },
    }
    await js.publish("enriched.entity.alert", json.dumps(payload).encode())

    from ingest.graph_writer import _process_message

    sub = await js.subscribe("enriched.entity.>", durable="test_infra_alert")
    msg = await sub.next_msg(timeout=5)
    await _process_message(pg_conn, msg)

    cursor = await pg_conn.execute(
        """
        select * from ag_catalog.cypher('core_graph', $$
            match (v:MonitoringAlert {fingerprint: 'testfp001'})
            return v.alertname, v.status
        $$) as (alertname agtype, status agtype)
        """
    )
    row = await cursor.fetchone()
    assert row is not None
    assert "HighCPUUsage" in str(row["alertname"])
