"""Integration tests for NATS JetStream ingest pipeline."""

from __future__ import annotations

import json

import pytest

from api.mcp.tools.ingest_event import ingest_event

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


async def test_wazuh_alert_arrives_on_stream(nats_conn) -> None:
    """Publish a Wazuh alert JSON and verify it arrives on the NATS stream."""
    js = nats_conn.jetstream()

    from nats.js.api import StreamConfig

    await js.add_stream(
        StreamConfig(
            name="INGEST_SIEM",
            subjects=["ingest.siem.>"],
            retention="limits",
            max_bytes=1_073_741_824,
        )
    )

    alert = {
        "timestamp": "2026-03-29T12:00:00Z",
        "rule": {
            "id": "5501",
            "description": "Login failure",
            "level": 5,
            "groups": ["authentication"],
        },
        "agent": {"id": "001", "name": "test-agent"},
        "data": {"srcip": "198.51.100.1"},
    }

    await js.publish("ingest.siem.alerts", json.dumps(alert).encode())

    sub = await js.subscribe("ingest.siem.alerts")
    msg = await sub.next_msg(timeout=5)
    received = json.loads(msg.data.decode())
    assert received["rule"]["id"] == "5501"


async def test_ocsf_event_via_mcp_tool(nats_conn) -> None:
    """Publish an OCSF event via the MCP ingest_event tool."""
    event = {
        "class_uid": 1,
        "category": "authentication",
        "time": "2026-03-29T12:00:00Z",
        "message": "Test authentication event",
    }

    result = await ingest_event(event)
    assert result["status"] == "ok"
    assert result["stream"] == "INGEST_API"
    assert isinstance(result["sequence"], int)


async def test_ocsf_event_arrives_on_stream(nats_conn) -> None:
    """Verify an OCSF event arrives on the ingest.api.events subject."""
    js = nats_conn.jetstream()

    from nats.js.api import StreamConfig

    await js.add_stream(
        StreamConfig(
            name="INGEST_API",
            subjects=["ingest.api.>"],
            retention="limits",
            max_bytes=1_073_741_824,
        )
    )

    sub = await js.subscribe("ingest.api.events")

    event = {
        "class_uid": 2,
        "category": "network_activity",
        "time": "2026-03-29T12:01:00Z",
        "message": "Test network event",
    }
    await js.publish("ingest.api.events", json.dumps(event).encode())

    msg = await sub.next_msg(timeout=5)
    received = json.loads(msg.data.decode())
    assert received["category"] == "network_activity"
