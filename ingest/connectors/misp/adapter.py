"""ingest.connectors.misp.adapter — MISP ZMQ feed consumer.

Connects to MISP's ZMQ pub/sub channel and converts events/attributes
to STIX-compatible entities for the core-graph ingest pipeline.

Distribution-to-TLP mapping:
    0 (Your org only)  → TLP:RED (3)
    1 (This community) → TLP:AMBER (2)
    2 (Connected)      → TLP:GREEN (1)
    3 (All communities)→ TLP:CLEAR (0)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

import nats
import zmq
import zmq.asyncio
from nats.js.api import StreamConfig

logger = logging.getLogger(__name__)

# Configuration
MISP_ZMQ_URL = os.environ.get("CG_MISP_ZMQ_URL", "tcp://localhost:50000")
MISP_API_URL = os.environ.get("CG_MISP_API_URL", "https://localhost")
MISP_API_KEY = os.environ.get("CG_MISP_API_KEY", "")
NATS_URL = os.environ.get("CG_NATS_URL", "nats://localhost:4222")

# MISP distribution level → TLP integer mapping
DISTRIBUTION_TLP_MAP: dict[int, int] = {
    0: 3,  # Your org → TLP:RED
    1: 2,  # This community → TLP:AMBER
    2: 1,  # Connected communities → TLP:GREEN
    3: 0,  # All communities → TLP:CLEAR
}

# MISP attribute type → STIX indicator pattern type
MISP_TYPE_TO_STIX: dict[str, str] = {
    "ip-src": "ipv4-addr",
    "ip-dst": "ipv4-addr",
    "domain": "domain-name",
    "hostname": "domain-name",
    "url": "url",
    "md5": "file:hashes.MD5",
    "sha1": "file:hashes.SHA-1",
    "sha256": "file:hashes.SHA-256",
    "email-src": "email-addr",
    "email-dst": "email-addr",
    "filename": "file:name",
    "mutex": "mutex:name",
    "regkey": "windows-registry-key:key",
}

# MISP attribute type → graph vertex label
MISP_TYPE_TO_LABEL: dict[str, str] = {
    "ip-src": "CanonicalIP",
    "ip-dst": "CanonicalIP",
    "domain": "CanonicalDomain",
    "hostname": "CanonicalDomain",
    "url": "Indicator",
    "md5": "Indicator",
    "sha1": "Indicator",
    "sha256": "Indicator",
    "email-src": "Indicator",
    "email-dst": "Indicator",
    "filename": "Indicator",
}


def _extract_tlp(distribution: int | str) -> int:
    """Map MISP distribution level to TLP integer."""
    return DISTRIBUTION_TLP_MAP.get(int(distribution), 2)


def _attribute_to_entity(attr: dict[str, Any], event_tlp: int) -> dict[str, Any] | None:
    """Convert a MISP attribute to a graph entity payload."""
    attr_type = attr.get("type", "")
    value = attr.get("value", "")

    if not value or attr_type not in MISP_TYPE_TO_LABEL:
        return None

    label = MISP_TYPE_TO_LABEL[attr_type]
    tlp = _extract_tlp(attr.get("distribution", 1))
    # Use the more restrictive TLP
    effective_tlp = max(tlp, event_tlp)

    entity: dict[str, Any] = {
        "label": label,
        "properties": {
            "value": value,
            "tlp": effective_tlp,
            "source": "misp",
        },
    }

    if label == "Indicator":
        entity["properties"]["indicator_type"] = attr_type

    return entity


def _event_to_entities(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract graph entities from a MISP event."""
    entities: list[dict[str, Any]] = []
    event_info = event.get("Event", event)

    event_tlp = _extract_tlp(event_info.get("distribution", 1))

    for attr in event_info.get("Attribute", []):
        entity = _attribute_to_entity(attr, event_tlp)
        if entity:
            entities.append(entity)

    # Process attributes inside objects
    for obj in event_info.get("Object", []):
        for attr in obj.get("Attribute", []):
            entity = _attribute_to_entity(attr, event_tlp)
            if entity:
                entities.append(entity)

    return entities


async def _ensure_stream(js: nats.js.JetStreamContext) -> None:
    """Ensure the MISP ingest stream exists."""
    await js.add_stream(
        StreamConfig(
            name="INGEST_MISP",
            subjects=["ingest.threatintel.misp"],
            retention="limits",
            max_bytes=1_073_741_824,
        )
    )


async def run(
    zmq_url: str = MISP_ZMQ_URL,
    nats_url: str = NATS_URL,
) -> None:
    """Main loop: consume from MISP ZMQ and publish entities to NATS."""
    nc = await nats.connect(nats_url)
    js = nc.jetstream()
    await _ensure_stream(js)

    ctx = zmq.asyncio.Context()
    sock = ctx.socket(zmq.SUB)
    sock.connect(zmq_url)
    sock.setsockopt_string(zmq.SUBSCRIBE, "misp_json_event")
    sock.setsockopt_string(zmq.SUBSCRIBE, "misp_json_attribute")

    logger.info("MISP connector started, consuming from %s", zmq_url)

    try:
        while True:
            try:
                raw = await sock.recv_string()
            except zmq.ZMQError:
                logger.warning("ZMQ receive error, reconnecting in 5s")
                await asyncio.sleep(5)
                sock.close()
                sock = ctx.socket(zmq.SUB)
                sock.connect(zmq_url)
                sock.setsockopt_string(zmq.SUBSCRIBE, "misp_json_event")
                sock.setsockopt_string(zmq.SUBSCRIBE, "misp_json_attribute")
                continue

            # ZMQ messages are prefixed with topic
            topic, _, payload_str = raw.partition(" ")

            try:
                payload = json.loads(payload_str)
            except json.JSONDecodeError:
                logger.warning("Invalid JSON from MISP ZMQ, skipping")
                continue

            if topic == "misp_json_event":
                entities = _event_to_entities(payload)
            elif topic == "misp_json_attribute":
                attr = payload.get("Attribute", payload)
                entity = _attribute_to_entity(attr, _extract_tlp(attr.get("distribution", 1)))
                entities = [entity] if entity else []
            else:
                continue

            for entity in entities:
                entity["properties"]["ingested_at"] = datetime.now(UTC).isoformat()
                await js.publish(
                    "ingest.threatintel.misp",
                    json.dumps(entity, default=str).encode(),
                )

            if entities:
                logger.info(
                    "Published %d entities from MISP %s",
                    len(entities),
                    topic,
                )
    finally:
        sock.close()
        ctx.term()
        await nc.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(run())
