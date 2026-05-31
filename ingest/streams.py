"""ingest.streams — Shared NATS JetStream definitions.

Centralises stream names, subjects, and quotas so the graph writer,
DLQ processor, and ingest adapters all agree on a single source of
truth. Stream creation is idempotent (NATS no-ops on identical config).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import nats
from nats.js.api import RetentionPolicy, StreamConfig

ENRICHED_STREAM = "ENRICHED"
ENRICHED_SUBJECTS = ["enriched.entity.>", "enriched.relationship.>"]

# Raw, source-shaped messages from the feed-style connectors (opencti, misp,
# osint, wazuh). A single work-queue stream consumed by the enrichment worker,
# which normalises them onto the ENRICHED stream. Connectors share this rather
# than each provisioning a bespoke stream, which would otherwise collide on the
# overlapping ingest.* subject space.
INGEST_STREAM = "INGEST"
INGEST_SUBJECTS = ["ingest.>"]

DLQ_STREAM = "DLQ"
DLQ_SUBJECTS = ["dlq.>"]

DEFAULT_MAX_BYTES = 1_073_741_824  # 1 GiB


def content_msg_id(payload: Any) -> str:
    """Deterministic, incarnation-independent dedup id for a message.

    SHA-256 over the canonical JSON of the message payload, prefixed
    ``sha256:``. Unlike a JetStream ``(stream, stream_seq)`` pair, this is stable
    across stream recreation: when a stream is deleted and rebuilt (DR/reset) its
    sequences restart at 1 and would otherwise collide with surviving claims in
    the 90-day ``processed_messages`` ledger, causing fresh deliveries to be
    acked as duplicates without ever being written. Hashing the content also
    makes the key version-aware for STIX — a new ``modified`` changes the payload
    and thus the id, so an updated object is reprocessed (and its TAXII
    ``t_recorded`` cursor refreshed) rather than suppressed — while exact
    byte-duplicate redeliveries collapse to the same id and dedup as intended.
    """
    canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"


async def ensure_enriched_stream(
    js: nats.js.JetStreamContext,
    *,
    name: str = ENRICHED_STREAM,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> None:
    """Ensure the enriched-payload work-queue stream exists.

    The default name is ``ENRICHED``; adapters may override it to bind
    their published subjects to a separately provisioned stream.
    """
    await js.add_stream(
        StreamConfig(
            name=name,
            subjects=ENRICHED_SUBJECTS,
            retention=RetentionPolicy.WORK_QUEUE,
            max_bytes=max_bytes,
        )
    )


async def ensure_ingest_stream(
    js: nats.js.JetStreamContext,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> None:
    """Ensure the raw-ingest work-queue stream exists (subjects ``ingest.>``)."""
    await js.add_stream(
        StreamConfig(
            name=INGEST_STREAM,
            subjects=INGEST_SUBJECTS,
            retention=RetentionPolicy.WORK_QUEUE,
            max_bytes=max_bytes,
        )
    )


async def ensure_dlq_stream(
    js: nats.js.JetStreamContext,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> None:
    """Ensure the DLQ work-queue stream exists."""
    await js.add_stream(
        StreamConfig(
            name=DLQ_STREAM,
            subjects=DLQ_SUBJECTS,
            retention=RetentionPolicy.WORK_QUEUE,
            max_bytes=max_bytes,
        )
    )
