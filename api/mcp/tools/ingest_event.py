"""api.mcp.tools.ingest_event — Event ingestion via NATS JetStream."""

from __future__ import annotations

import json
import logging
from typing import Any

import nats
from nats.js.api import StreamConfig
from pydantic import BaseModel

logger = logging.getLogger(__name__)

NATS_URL = "nats://localhost:4222"

# Required OCSF fields for basic validation
REQUIRED_FIELDS = {"class_uid", "category", "time"}


class IngestEventInput(BaseModel):
    """Input model for ingest_event tool."""

    event: dict[str, Any]


class IngestEventResult(BaseModel):
    """Output model for ingest_event tool."""

    status: str
    sequence: int | None = None
    stream: str | None = None


def _validate_ocsf_event(event: dict[str, Any]) -> list[str]:
    """Basic OCSF schema validation.

    Returns a list of validation errors (empty if valid).
    """
    errors: list[str] = []
    for field in REQUIRED_FIELDS:
        if field not in event:
            errors.append(f"Missing required field: {field}")
    if "category" in event:
        valid_categories = {
            "authentication",
            "network_activity",
            "file_activity",
            "finding",
            "process_activity",
            "system_activity",
            "web_activity",
            "other",
        }
        if event["category"] not in valid_categories:
            errors.append(f"Invalid category: {event['category']}")
    return errors


async def ingest_event(event: dict[str, Any]) -> dict[str, Any]:
    """Validate and publish an OCSF event to NATS JetStream.

    Args:
        event: OCSF-normalised event dictionary.

    Returns:
        Acknowledgement with status and sequence number.
    """
    # Validate
    errors = _validate_ocsf_event(event)
    if errors:
        return {"status": "error", "errors": errors}

    # Publish to NATS
    nc = await nats.connect(NATS_URL)
    try:
        js = nc.jetstream()
        await js.add_stream(
            StreamConfig(
                name="INGEST_API",
                subjects=["ingest.api.>"],
                retention="limits",
                max_bytes=1_073_741_824,
            )
        )
        ack = await js.publish(
            "ingest.api.events",
            json.dumps(event, default=str).encode(),
        )

        # TODO: log to audit trail
        logger.info("Event ingested: stream=%s seq=%d", ack.stream, ack.seq)
        return {
            "status": "ok",
            "sequence": ack.seq,
            "stream": ack.stream,
        }
    finally:
        await nc.close()
