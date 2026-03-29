"""ingest.dlq.processor — Dead-letter queue processor.

Consumes failed messages from NATS JetStream ``dlq.>`` subjects.
Retries with exponential backoff up to a configurable maximum, then
archives to the ``dlq_archive`` PostgreSQL table.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import UTC, datetime
from typing import Any

import nats
import psycopg
from nats.js.api import ConsumerConfig, StreamConfig
from psycopg.rows import dict_row

logger = logging.getLogger(__name__)

MAX_RETRIES = int(os.environ.get("CG_DLQ_MAX_RETRIES", "3"))
BASE_BACKOFF_S = 2


async def _ensure_streams(js: nats.js.JetStreamContext) -> None:
    """Ensure the DLQ stream exists."""
    await js.add_stream(
        StreamConfig(
            name="DLQ",
            subjects=["dlq.>"],
            retention="work_queue",
            max_bytes=1_073_741_824,
        )
    )


async def _archive_message(
    conn: psycopg.AsyncConnection[Any],
    original_subject: str,
    payload: dict[str, Any],
    error_message: str,
    retry_count: int,
    first_failed: str,
) -> None:
    """Write a permanently failed message to the dlq_archive table."""
    await conn.execute(
        """
        insert into dlq_archive
            (original_subject, payload, error_message, retry_count,
             first_failed, last_failed)
        values (%s, %s, %s, %s, %s, now())
        """,
        (
            original_subject,
            json.dumps(payload),
            error_message,
            retry_count,
            first_failed,
        ),
    )
    await conn.commit()


async def _write_audit_entry(
    conn: psycopg.AsyncConnection[Any],
    operation: str,
    subject: str,
    retry_count: int,
) -> None:
    """Log DLQ event to audit trail."""
    await conn.execute(
        """
        insert into audit_log
            (entity_label, operation, actor, correlation_id)
        values (%s, %s, %s, %s)
        """,
        (
            f"dlq:{subject}",
            operation,
            "dlq_processor",
            uuid.uuid4(),
        ),
    )
    await conn.commit()


# -- Counters for metrics (consumed by ingest.metrics) -------------------------
dlq_total = 0
dlq_retried = 0
dlq_archived = 0


async def _process_dlq_message(
    conn: psycopg.AsyncConnection[Any],
    js: nats.js.JetStreamContext,
    msg: Any,
) -> None:
    """Process a single DLQ message: retry or archive."""
    global dlq_total, dlq_retried, dlq_archived
    dlq_total += 1

    try:
        payload = json.loads(msg.data.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.error("Invalid DLQ message payload, acking to discard")
        await msg.ack()
        return

    original_subject = payload.get("original_subject", "unknown")
    original_payload = payload.get("payload", {})
    error_message = payload.get("error", "unknown error")
    retry_count = payload.get("retry_count", 0)
    first_failed = payload.get("first_failed", datetime.now(UTC).isoformat())

    if retry_count < MAX_RETRIES:
        # Exponential backoff
        backoff = BASE_BACKOFF_S ** (retry_count + 1)
        await asyncio.sleep(backoff)

        # Republish to original subject with incremented retry count
        retry_payload = {
            **original_payload,
            "_dlq_retry_count": retry_count + 1,
        }
        await js.publish(
            original_subject,
            json.dumps(retry_payload, default=str).encode(),
        )
        dlq_retried += 1
        await _write_audit_entry(conn, "DLQ_RETRY", original_subject, retry_count + 1)
        logger.info(
            "DLQ retry %d/%d for %s",
            retry_count + 1,
            MAX_RETRIES,
            original_subject,
        )
    else:
        # Archive permanently
        await _archive_message(
            conn,
            original_subject,
            original_payload,
            error_message,
            retry_count,
            first_failed,
        )
        dlq_archived += 1
        await _write_audit_entry(conn, "DLQ_ARCHIVE", original_subject, retry_count)
        logger.warning(
            "DLQ archived after %d retries: %s",
            retry_count,
            original_subject,
        )

    await msg.ack()


async def run(
    pg_dsn: str = "postgresql://cg_admin:cg_dev_only@localhost:5432/core_graph",
    nats_url: str = "nats://localhost:4222",
) -> None:
    """Main loop: consume from DLQ and retry or archive."""
    nc = await nats.connect(nats_url)
    js = nc.jetstream()
    await _ensure_streams(js)

    conn = await psycopg.AsyncConnection.connect(pg_dsn, row_factory=dict_row)
    await conn.set_autocommit(False)

    sub = await js.subscribe(
        "dlq.>",
        durable="dlq_processor",
        config=ConsumerConfig(ack_wait=60),
    )

    logger.info("DLQ processor started, consuming dlq.>")

    try:
        async for msg in sub.messages:
            try:
                await _process_dlq_message(conn, js, msg)
            except Exception:
                logger.exception("Error processing DLQ message")
                await conn.rollback()
                await msg.nak()
    finally:
        await conn.close()
        await nc.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(run())
