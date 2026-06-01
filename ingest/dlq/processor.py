"""ingest.dlq.processor — Dead-letter queue processor.

Consumes failed messages from NATS JetStream ``dlq.>`` subjects.
Retries with exponential backoff up to a configurable maximum, then
archives to the ``dlq_archive`` PostgreSQL table.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import random
import uuid
from datetime import UTC, datetime
from typing import Any

import nats
import psycopg
from nats.js.api import ConsumerConfig
from psycopg.rows import dict_row

from api.config import NATS_URL, PG_DSN
from ingest.metrics import dlq_by_class_total
from ingest.streams import ensure_dlq_stream

logger = logging.getLogger(__name__)

MAX_RETRIES = int(os.environ.get("CG_DLQ_MAX_RETRIES", "3"))
BASE_BACKOFF_S = 2


def classify_error(error_message: str) -> str:
    """Classify a DLQ error message into a category.

    Returns one of: schema_mismatch, connection_error, constraint_violation,
    timeout, authorization, unknown.
    """
    msg = error_message.lower()
    if any(kw in msg for kw in ("schema", "validation", "invalid", "missing field")):
        return "schema_mismatch"
    if any(kw in msg for kw in ("connection", "refused", "unreachable", "dns")):
        return "connection_error"
    if any(kw in msg for kw in ("constraint", "unique", "duplicate", "foreign key", "violates")):
        return "constraint_violation"
    if any(kw in msg for kw in ("timeout", "timed out", "deadline")):
        return "timeout"
    authz_kw = ("authorization", "forbidden", "permission", "denied", "401", "403")
    if any(kw in msg for kw in authz_kw):
        return "authorization"
    return "unknown"


async def _archive_message(
    conn: psycopg.AsyncConnection[Any],
    original_subject: str,
    payload: dict[str, Any],
    error_message: str,
    retry_count: int,
    first_failed: str,
    error_class: str,
) -> None:
    """Write a permanently failed message to the dlq_archive table."""
    await conn.execute(
        """
        insert into dlq_archive
            (original_subject, payload, error_message, retry_count,
             first_failed, last_failed, error_class)
        values (%s, %s, %s, %s, %s, now(), %s)
        """,
        (
            original_subject,
            json.dumps(payload),
            error_message,
            retry_count,
            first_failed,
            error_class,
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
        # Exponential backoff with full jitter to avoid thundering-herd
        # against the upstream that originally rejected the message.
        # Reference: AWS Architecture Blog, "Exponential Backoff and Jitter"
        # (Marc Brooker, 2015). At retry_count=0 the window is 0..2 s;
        # at retry_count=2 (max with MAX_RETRIES=3) the window is 0..8 s.
        ceiling = BASE_BACKOFF_S ** (retry_count + 1)
        backoff = random.uniform(0, ceiling)  # noqa: S311 — not crypto
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
        error_class = classify_error(error_message)
        await _archive_message(
            conn,
            original_subject,
            original_payload,
            error_message,
            retry_count,
            first_failed,
            error_class,
        )
        dlq_archived += 1
        dlq_by_class_total.labels(error_class=error_class).inc()
        await _write_audit_entry(conn, "DLQ_ARCHIVE", original_subject, retry_count)
        logger.warning(
            "DLQ archived after %d retries: %s (class=%s)",
            retry_count,
            original_subject,
            error_class,
        )

    await msg.ack()


async def _open_connection(pg_dsn: str) -> psycopg.AsyncConnection[Any]:
    """Open a fresh DLQ database connection (dict rows, autocommit off)."""
    conn = await psycopg.AsyncConnection.connect(pg_dsn, row_factory=dict_row)
    await conn.set_autocommit(False)
    return conn


async def _safe_rollback(conn: psycopg.AsyncConnection[Any]) -> None:
    """Roll back, swallowing errors raised by an already-broken connection."""
    with contextlib.suppress(Exception):
        await conn.rollback()


async def _safe_close(conn: psycopg.AsyncConnection[Any]) -> None:
    """Close, swallowing errors raised by an already-broken connection."""
    with contextlib.suppress(Exception):
        await conn.close()


async def run(
    pg_dsn: str | None = None,
    nats_url: str | None = None,
) -> None:
    """Main loop: consume from DLQ and retry or archive.

    The PostgreSQL connection is long-lived. If it drops (server restart,
    failover, idle timeout) the next statement raises
    ``psycopg.OperationalError`` and, without recovery, every subsequent
    delivery would keep failing against the same dead handle -- the processor
    would silently stop draining the queue. The loop therefore reconnects on
    ``OperationalError`` (and re-checks ``conn.closed`` before each message),
    NAK-ing the in-flight delivery so JetStream redelivers it against the
    fresh connection.
    """
    dsn = pg_dsn or PG_DSN
    nc = await nats.connect(nats_url or NATS_URL)
    js = nc.jetstream()
    await ensure_dlq_stream(js)

    conn = await _open_connection(dsn)

    sub = await js.subscribe(
        "dlq.>",
        durable="dlq_processor",
        config=ConsumerConfig(ack_wait=60),
    )

    logger.info("DLQ processor started, consuming dlq.>")

    try:
        async for msg in sub.messages:
            try:
                if conn.closed:
                    logger.warning("DLQ database connection closed; reconnecting")
                    conn = await _open_connection(dsn)
                await _process_dlq_message(conn, js, msg)
            except psycopg.OperationalError:
                logger.exception("DLQ database connection lost; reconnecting and redelivering")
                await _safe_close(conn)
                try:
                    conn = await _open_connection(dsn)
                except psycopg.OperationalError:
                    logger.exception("DLQ reconnect failed; will retry on the next delivery")
                await msg.nak()
            except Exception:
                logger.exception("Error processing DLQ message")
                await _safe_rollback(conn)
                await msg.nak()
    finally:
        await _safe_close(conn)
        await nc.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(run())
