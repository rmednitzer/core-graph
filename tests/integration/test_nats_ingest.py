"""Integration tests for the NATS JetStream ingest pipeline.

Raw source events land on the single canonical ``INGEST`` work-queue stream
(subjects ``ingest.>``) defined in ``ingest.streams`` — the enrichment worker
consumes it and normalises events onto ``enriched.entity.*`` for the writer.
"""

from __future__ import annotations

import json

import pytest

from api.mcp.tools.ingest_event import ingest_event
from ingest.streams import INGEST_STREAM

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


async def test_wazuh_alert_arrives_on_stream(nats_js) -> None:
    """A Wazuh alert published to ingest.siem.* lands on the INGEST stream."""
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
    ack = await nats_js.publish("ingest.siem.alerts", json.dumps(alert).encode())
    assert ack.stream == INGEST_STREAM

    msg = await nats_js.get_msg(INGEST_STREAM, seq=ack.seq)
    received = json.loads(msg.data.decode())
    assert received["rule"]["id"] == "5501"


async def test_ocsf_event_via_mcp_tool(nats_js) -> None:
    """Publish an OCSF event via the MCP ingest_event tool."""
    event = {
        "class_uid": 1,
        "category": "authentication",
        "time": "2026-03-29T12:00:00Z",
        "message": "Test authentication event",
    }

    result = await ingest_event(event)
    assert result["status"] == "ok"
    assert result["stream"] == INGEST_STREAM
    assert isinstance(result["sequence"], int)


async def test_ocsf_event_arrives_on_stream(nats_js) -> None:
    """An OCSF event published to ingest.api.events lands on the INGEST stream."""
    event = {
        "class_uid": 2,
        "category": "network_activity",
        "time": "2026-03-29T12:01:00Z",
        "message": "Test network event",
    }
    ack = await nats_js.publish("ingest.api.events", json.dumps(event).encode())
    assert ack.stream == INGEST_STREAM

    msg = await nats_js.get_msg(INGEST_STREAM, seq=ack.seq)
    received = json.loads(msg.data.decode())
    assert received["category"] == "network_activity"
