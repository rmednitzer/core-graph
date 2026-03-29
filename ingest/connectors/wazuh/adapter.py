"""ingest.connectors.wazuh.adapter — Wazuh alert ingest adapter.

Reads Wazuh alert JSON from stdin, extracts entities, normalises to
OCSF-inspired event format, and publishes to NATS JetStream.
"""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import UTC, datetime
from typing import Any

import nats
from nats.js.api import StreamConfig


async def connect_nats(url: str = "nats://localhost:4222") -> nats.NATS:
    """Connect to NATS and ensure the ingest stream exists."""
    nc = await nats.connect(url)
    js = nc.jetstream()
    await js.add_stream(
        StreamConfig(
            name="INGEST_SIEM",
            subjects=["ingest.siem.>"],
            retention="limits",
            max_bytes=1_073_741_824,  # 1 GiB
        )
    )
    return nc


def extract_entities(alert: dict[str, Any]) -> dict[str, Any]:
    """Extract structured entities from a Wazuh alert."""
    data = alert.get("data", {})
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})

    return {
        "source_ip": data.get("srcip"),
        "destination_ip": data.get("dstip"),
        "username": data.get("srcuser") or data.get("dstuser"),
        "file_hashes": {
            "md5": data.get("md5_after"),
            "sha1": data.get("sha1_after"),
            "sha256": data.get("sha256_after"),
        },
        "rule_id": rule.get("id"),
        "rule_description": rule.get("description"),
        "rule_level": rule.get("level"),
        "agent_name": agent.get("name"),
        "agent_id": agent.get("id"),
    }


def normalise_to_ocsf(alert: dict[str, Any], entities: dict[str, Any]) -> dict[str, Any]:
    """Map Wazuh alert fields to OCSF-inspired event structure."""
    rule = alert.get("rule", {})
    groups = rule.get("groups", [])

    # OCSF category mapping based on Wazuh rule groups
    category = "other"
    if "authentication" in groups or "sshd" in groups:
        category = "authentication"
    elif "firewall" in groups or "iptables" in groups:
        category = "network_activity"
    elif "syscheck" in groups:
        category = "file_activity"
    elif "rootcheck" in groups or "vulnerability-detector" in groups:
        category = "finding"

    return {
        "class_uid": 1,  # placeholder — real OCSF class mapping is future work
        "category": category,
        "severity_id": min((entities.get("rule_level") or 0), 10),
        "time": alert.get("timestamp", datetime.now(UTC).isoformat()),
        "message": entities.get("rule_description", ""),
        "metadata": {
            "product": {"name": "Wazuh", "vendor_name": "Wazuh Inc."},
            "version": "1.0.0",
            "original_time": alert.get("timestamp"),
        },
        "src_endpoint": {"ip": entities.get("source_ip")},
        "dst_endpoint": {"ip": entities.get("destination_ip")},
        "actor": {"user": {"name": entities.get("username")}},
        "finding_info": {
            "uid": entities.get("rule_id"),
            "title": entities.get("rule_description"),
        },
        "observables": _build_observables(entities),
        "raw_event": alert,
    }


def _build_observables(entities: dict[str, Any]) -> list[dict[str, Any]]:
    """Build OCSF observable list from extracted entities."""
    observables: list[dict[str, Any]] = []
    if entities.get("source_ip"):
        observables.append({"type": "ip", "value": entities["source_ip"]})
    if entities.get("destination_ip"):
        observables.append({"type": "ip", "value": entities["destination_ip"]})
    if entities.get("username"):
        observables.append({"type": "user", "value": entities["username"]})
    for algo, val in (entities.get("file_hashes") or {}).items():
        if val:
            observables.append({"type": f"hash_{algo}", "value": val})
    return observables


async def process_alert(nc: nats.NATS, alert: dict[str, Any]) -> None:
    """Process a single Wazuh alert and publish to NATS."""
    entities = extract_entities(alert)
    event = normalise_to_ocsf(alert, entities)
    js = nc.jetstream()
    await js.publish(
        "ingest.siem.alerts",
        json.dumps(event, default=str).encode(),
    )


async def main() -> None:
    """Read Wazuh alerts from stdin and publish to NATS JetStream."""
    nc = await connect_nats()
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                print("WARN: skipping invalid JSON line", file=sys.stderr)
                continue
            await process_alert(nc, alert)
    finally:
        await nc.close()


if __name__ == "__main__":
    asyncio.run(main())
