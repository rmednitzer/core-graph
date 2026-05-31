"""Integration tests for Layer 7 infrastructure entity ingest pipeline."""

from __future__ import annotations

import json

import pytest

from ingest.canonical import canonical_key
from tests.integration._helpers import poll_cypher

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


async def test_publish_and_merge_host(nats_js, graph_writer, pg_conn) -> None:
    """Publish a Host entity and verify the writer merges it into AGE."""
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
    await nats_js.publish("enriched.entity.host", json.dumps(payload).encode())

    rows = await poll_cypher(
        pg_conn,
        """
        select * from ag_catalog.cypher('core_graph', $$
            match (v:Host {name: 'axiom'})
            return v.name, v.host_type, v.status
        $$) as (name agtype, host_type agtype, status agtype)
        """,
    )
    assert rows, "Host vertex should exist after graph write"
    assert "axiom" in str(rows[0]["name"])


async def test_publish_and_merge_monitoring_alert(nats_js, graph_writer, pg_conn) -> None:
    """Publish a MonitoringAlert entity and verify the writer merges it."""
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
            "ends_at": "",
        },
    }
    await nats_js.publish("enriched.entity.alert", json.dumps(payload).encode())

    rows = await poll_cypher(
        pg_conn,
        """
        select * from ag_catalog.cypher('core_graph', $$
            match (v:MonitoringAlert {fingerprint: 'testfp001'})
            return v.alertname, v.status
        $$) as (alertname agtype, status agtype)
        """,
    )
    assert rows, "MonitoringAlert vertex should exist after graph write"
    assert "HighCPUUsage" in str(rows[0]["alertname"])
