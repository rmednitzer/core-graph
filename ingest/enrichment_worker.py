"""ingest.enrichment_worker — raw ingest -> enriched normalisation worker.

Consumes the feed-style connectors' source-shaped messages from the INGEST
work-queue stream (``ingest.>``), maps each to canonical entity envelopes via
ingest.enrichment, and republishes them onto the ENRICHED stream that the
graph writer consumes. This closes the gap whereby opencti/misp/osint/wazuh
published to ``ingest.*`` with no consumer downstream.

Mirrors the connect/subscribe/ack and DLQ-on-error pattern of
ingest.graph_writer so at-least-once redelivery is handled consistently
(re-enrichment is safe: the writer's MERGE upserts are idempotent).
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import nats
from nats.js.api import ConsumerConfig

from api.config import NATS_URL
from ingest.enrichment import enrich
from ingest.metrics import adapter_entities_total
from ingest.streams import (
    ensure_dlq_stream,
    ensure_enriched_stream,
    ensure_ingest_stream,
    jetstream_delivery_key,
)

logger = logging.getLogger(__name__)

# See ingest/graph_writer.py for the readiness-marker rationale.
_READY_MARKER = Path(tempfile.gettempdir()) / "enrichment-worker.ready"


def _enriched_subject(ingest_subject: str) -> str:
    """ingest.threatintel.misp -> enriched.entity.threatintel.misp."""
    suffix = ingest_subject.removeprefix("ingest.")
    return f"enriched.entity.{suffix}"


async def _process_message(js: nats.js.JetStreamContext, msg: Any) -> None:
    """Enrich one raw message and publish the resulting entity envelopes."""
    payload = json.loads(msg.data.decode())
    envelopes = enrich(msg.subject, payload)
    if not envelopes:
        logger.debug("No writable entity from %s (deferred or unmapped)", msg.subject)
        return
    target = _enriched_subject(msg.subject)
    # Carry a stable idempotency key from THIS ingest delivery into each enriched
    # envelope. If the worker crashes after publishing but before acking, the
    # ingest message is redelivered and re-enriched; the graph writer dedups on
    # this key (not the new ENRICHED sequence it would otherwise get), so the
    # audit/temporal rows are not duplicated. One ingest message fans out to N
    # envelopes, so the index keeps each enriched message's key distinct.
    src_key = jetstream_delivery_key(msg)
    for i, envelope in enumerate(envelopes):
        if src_key is not None:
            envelope["_idem"] = f"{src_key}:{i}"
        await js.publish(target, json.dumps(envelope, default=str).encode())
        adapter_entities_total.labels(adapter="enrichment", label=envelope["label"]).inc()


async def run(nats_url: str | None = None) -> None:
    """Main loop: consume ingest.>, enrich, and publish enriched.entity.>."""
    nc = await nats.connect(nats_url or NATS_URL)
    js = nc.jetstream()
    await ensure_ingest_stream(js)
    await ensure_enriched_stream(js)
    await ensure_dlq_stream(js)

    sub = await js.subscribe(
        "ingest.>",
        durable="enrichment_worker",
        config=ConsumerConfig(ack_wait=30),
    )
    logger.info("Enrichment worker started, consuming ingest.> -> enriched.entity.>")
    _READY_MARKER.touch(exist_ok=True)

    try:
        async for msg in sub.messages:
            try:
                await _process_message(js, msg)
                await msg.ack()
            except Exception as exc:
                logger.exception("Error enriching message, publishing to DLQ")
                try:
                    dlq_payload = {
                        "original_subject": msg.subject,
                        "payload": json.loads(msg.data.decode()) if msg.data else {},
                        "error": str(exc),
                        "retry_count": 0,
                        "first_failed": datetime.now(UTC).isoformat(),
                    }
                    await js.publish(
                        f"dlq.{msg.subject}",
                        json.dumps(dlq_payload, default=str).encode(),
                    )
                except Exception:
                    logger.exception("Failed to publish to DLQ")
                await msg.ack()
    finally:
        _READY_MARKER.unlink(missing_ok=True)
        await nc.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(run())
