"""ingest.connectors.opencti.adapter — OpenCTI STIX 2.1 ingest connector.

Connects to OpenCTI's SSE stream, consumes STIX 2.1 bundle events,
maps them to graph vertex labels, and publishes to NATS JetStream.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

import httpx
import nats
from nats.js.api import StreamConfig

from api.config import NATS_URL

logger = logging.getLogger(__name__)

OPENCTI_URL = os.environ.get("OPENCTI_URL", "http://localhost:8080")
OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN", "")

# STIX SDO type → AGE vertex label (from docs/ontology/stix-mapping.md)
STIX_TO_LABEL: dict[str, str] = {
    "threat-actor": "ThreatActor",
    "campaign": "Campaign",
    "attack-pattern": "AttackPattern",
    "indicator": "Indicator",
    "malware": "Malware",
    "vulnerability": "Vulnerability",
    "tool": "Tool",
    "intrusion-set": "IntrusionSet",
    "identity": "Identity",
    "location": "Location",
    "report": "Report",
}

# STIX SCO type → canonical entity label
SCO_TO_LABEL: dict[str, str] = {
    "ipv4-addr": "CanonicalIP",
    "ipv6-addr": "CanonicalIP",
    "domain-name": "CanonicalDomain",
    "email-addr": "CanonicalPerson",
    "file": "Indicator",
}

# TLP marking definition UUIDs → integer levels
TLP_MARKING_MAP: dict[str, int] = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": 0,  # TLP:CLEAR
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": 1,  # TLP:GREEN
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": 2,  # TLP:AMBER
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": 3,  # TLP:AMBER+STRICT
    "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37": 4,  # TLP:RED
}


def _extract_tlp(stix_object: dict[str, Any]) -> int:
    """Extract TLP level from object_marking_refs."""
    markings = stix_object.get("object_marking_refs", [])
    max_tlp = 0
    for marking_id in markings:
        tlp = TLP_MARKING_MAP.get(marking_id)
        if tlp is not None and tlp > max_tlp:
            max_tlp = tlp
    return max_tlp


def _map_stix_object(stix_object: dict[str, Any]) -> dict[str, Any] | None:
    """Map a STIX object to a graph entity payload for NATS."""
    stix_type = stix_object.get("type", "")

    # Try SDO mapping first, then SCO
    label = STIX_TO_LABEL.get(stix_type) or SCO_TO_LABEL.get(stix_type)
    if label is None:
        logger.debug("Unmapped STIX type: %s", stix_type)
        return None

    tlp_level = _extract_tlp(stix_object)

    # Extract core properties
    properties: dict[str, Any] = {
        "stix_id": stix_object.get("id", ""),
        "stix_type": stix_type,
        "name": stix_object.get("name", ""),
        "description": stix_object.get("description", ""),
        "created": stix_object.get("created", ""),
        "modified": stix_object.get("modified", ""),
        "tlp": tlp_level,
    }

    # Type-specific properties
    if stix_type == "indicator":
        properties["pattern"] = stix_object.get("pattern", "")
        properties["pattern_type"] = stix_object.get("pattern_type", "")
        properties["valid_from"] = stix_object.get("valid_from", "")
        properties["valid_until"] = stix_object.get("valid_until", "")
    elif stix_type == "threat-actor":
        properties["aliases"] = stix_object.get("aliases", [])
        properties["roles"] = stix_object.get("roles", [])
        properties["sophistication"] = stix_object.get("sophistication", "")
    elif stix_type == "malware":
        properties["malware_types"] = stix_object.get("malware_types", [])
        properties["is_family"] = stix_object.get("is_family", False)
    elif stix_type == "vulnerability":
        # Extract CVE from external_references
        for ref in stix_object.get("external_references", []):
            if ref.get("source_name") == "cve":
                properties["cve_id"] = ref.get("external_id", "")
                break
    elif stix_type in ("ipv4-addr", "ipv6-addr"):
        properties["value"] = stix_object.get("value", "")
    elif stix_type == "domain-name":
        properties["value"] = stix_object.get("value", "").lower()
    elif stix_type == "email-addr":
        properties["value"] = stix_object.get("value", "")

    return {
        "label": label,
        "properties": properties,
        "source": "opencti",
        "stix_event_type": stix_object.get("_event_type", "create"),
    }


async def _consume_sse(
    opencti_url: str,
    token: str,
    js: nats.js.JetStreamContext,
) -> None:
    """Consume SSE events from OpenCTI and publish to NATS."""
    url = f"{opencti_url}/stream"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "text/event-stream",
    }

    while True:
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream("GET", url, headers=headers) as response:
                    response.raise_for_status()
                    logger.info("Connected to OpenCTI SSE stream")

                    event_data = ""
                    async for line in response.aiter_lines():
                        if line.startswith("data:"):
                            event_data = line[5:].strip()
                        elif line == "" and event_data:
                            # Process complete SSE event
                            try:
                                bundle = json.loads(event_data)
                                fallback = [bundle] if "type" in bundle else []
                                objects = bundle.get("objects", fallback)
                                for stix_obj in objects:
                                    payload = _map_stix_object(stix_obj)
                                    if payload is not None:
                                        await js.publish(
                                            "ingest.threatintel.opencti",
                                            json.dumps(payload, default=str).encode(),
                                        )
                                        logger.debug(
                                            "Published %s/%s",
                                            payload["label"],
                                            payload["properties"].get("stix_id", ""),
                                        )
                            except json.JSONDecodeError:
                                logger.warning("Invalid JSON in SSE event")
                            event_data = ""
        except httpx.HTTPStatusError as exc:
            logger.error("OpenCTI SSE HTTP error %d, reconnecting in 10s", exc.response.status_code)
            await asyncio.sleep(10)
        except (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError):
            logger.warning("OpenCTI SSE connection lost, reconnecting in 5s")
            await asyncio.sleep(5)
        except Exception:
            logger.exception("Unexpected error in OpenCTI SSE consumer, reconnecting in 15s")
            await asyncio.sleep(15)


async def run(
    opencti_url: str | None = None,
    opencti_token: str | None = None,
    nats_url: str | None = None,
) -> None:
    """Main entry point for the OpenCTI ingest connector."""
    url = opencti_url or OPENCTI_URL
    token = opencti_token or OPENCTI_TOKEN
    nats_addr = nats_url or NATS_URL

    if not token:
        raise ValueError("OPENCTI_TOKEN is required. Set via environment variable or parameter.")

    nc = await nats.connect(nats_addr)
    js = nc.jetstream()

    # Ensure the ingest stream exists
    await js.add_stream(
        StreamConfig(
            name="INGEST_THREATINTEL",
            subjects=["ingest.threatintel.>"],
            retention="limits",
            max_bytes=1_073_741_824,
        )
    )

    logger.info("Starting OpenCTI connector: %s → NATS %s", url, nats_addr)

    try:
        await _consume_sse(url, token, js)
    finally:
        await nc.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(run())
