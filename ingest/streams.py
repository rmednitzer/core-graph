"""ingest.streams — Shared NATS JetStream definitions.

Centralises stream names, subjects, and quotas so the graph writer,
DLQ processor, and ingest adapters all agree on a single source of
truth. Stream creation is idempotent (NATS no-ops on identical config).
"""

from __future__ import annotations

import nats
from nats.js.api import StreamConfig

ENRICHED_STREAM = "ENRICHED"
ENRICHED_SUBJECTS = ["enriched.entity.>", "enriched.relationship.>"]

DLQ_STREAM = "DLQ"
DLQ_SUBJECTS = ["dlq.>"]

DEFAULT_MAX_BYTES = 1_073_741_824  # 1 GiB


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
            retention="work_queue",
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
            retention="work_queue",
            max_bytes=max_bytes,
        )
    )
