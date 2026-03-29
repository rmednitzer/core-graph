"""ingest.connectors.osint.adapter — Generic OSINT feed ingest adapter.

Periodically fetches configured OSINT feeds, extracts IOCs via Tier 1 NER,
and publishes to NATS JetStream. Caches responses in Valkey with TTL.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import nats
import psycopg
import redis.asyncio as redis
from nats.js.api import StreamConfig

from api.config import NATS_URL, PG_DSN, VALKEY_URL
from ingest.connectors.osint.config import FeedSource, load_feeds_config
from ingest.ner.tier1_regex import extract_iocs

logger = logging.getLogger(__name__)


async def _fetch_feed(
    client: httpx.AsyncClient,
    feed: FeedSource,
    cache: redis.Redis,
) -> list[dict[str, Any]] | None:
    """Fetch a feed URL, respecting cache TTL.

    Returns parsed data or None if cached / fetch failed.
    """
    cache_key = f"osint:feed:{feed.name}:last"

    # Check cache
    cached = await cache.get(cache_key)
    if cached is not None:
        logger.debug("Feed %s: cached, skipping", feed.name)
        return None

    try:
        response = await client.get(feed.url, timeout=30)
        response.raise_for_status()
    except httpx.HTTPError:
        logger.warning("Feed %s: fetch failed", feed.name, exc_info=True)
        return None

    # Cache with TTL equal to feed interval
    await cache.set(cache_key, "1", ex=feed.interval)

    if feed.format == "json":
        try:
            data = response.json()
            if isinstance(data, dict):
                # Many feeds wrap results in a key
                for key in ("urls", "data", "results", "items", "objects", "response"):
                    if key in data and isinstance(data[key], list):
                        return data[key]
                return [data]
            elif isinstance(data, list):
                return data
        except json.JSONDecodeError:
            logger.warning("Feed %s: invalid JSON response", feed.name)
            return None
    elif feed.format == "csv":
        lines = response.text.strip().splitlines()
        # Skip comment lines
        data_lines = [line for line in lines if not line.startswith("#")]
        return [{"raw": line} for line in data_lines if line.strip()]

    return None


def _extract_entities_from_record(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Run Tier 1 NER on text fields within a feed record."""
    # Concatenate all string values for NER extraction
    text_parts: list[str] = []
    for val in record.values():
        if isinstance(val, str):
            text_parts.append(val)
        elif isinstance(val, dict):
            for sub_val in val.values():
                if isinstance(sub_val, str):
                    text_parts.append(sub_val)

    combined_text = " ".join(text_parts)
    if not combined_text.strip():
        return []

    iocs = extract_iocs(combined_text)
    return [
        {
            "type": ioc["type"],
            "value": ioc["value"],
            "source_record": record,
        }
        for ioc in iocs
    ]


async def _write_audit_entry(
    feed_name: str,
    entity_count: int,
    pg_dsn: str,
) -> None:
    """Log feed fetch to audit trail."""
    try:
        async with await psycopg.AsyncConnection.connect(pg_dsn) as conn:
            await conn.execute(
                """
                insert into audit_log
                    (entity_label, operation, actor, correlation_id)
                values (%s, %s, %s, %s)
                """,
                (
                    f"osint:{feed_name}",
                    "FETCH",
                    "osint_adapter",
                    uuid.uuid4(),
                ),
            )
            await conn.commit()
    except Exception:
        logger.warning("Failed to write audit entry for feed %s", feed_name, exc_info=True)


async def _process_feed(
    feed: FeedSource,
    client: httpx.AsyncClient,
    js: nats.js.JetStreamContext,
    cache: redis.Redis,
    pg_dsn: str,
) -> None:
    """Fetch and process a single feed."""
    records = await _fetch_feed(client, feed, cache)
    if records is None:
        return

    entity_count = 0
    for record in records:
        entities = _extract_entities_from_record(record)
        for entity in entities:
            payload = {
                "label": entity["type"],
                "value": entity["value"],
                "source": feed.name,
                "timestamp": datetime.now(UTC).isoformat(),
            }
            await js.publish(
                feed.subject,
                json.dumps(payload, default=str).encode(),
            )
            entity_count += 1

    logger.info("Feed %s: published %d entities", feed.name, entity_count)
    await _write_audit_entry(feed.name, entity_count, pg_dsn)


async def run(
    config_path: str | None = None,
    nats_url: str | None = None,
    valkey_url: str | None = None,
    pg_dsn: str | None = None,
) -> None:
    """Main loop: periodically fetch all configured feeds."""
    config = load_feeds_config(config_path)
    nats_addr = nats_url or NATS_URL
    valkey_addr = valkey_url or VALKEY_URL
    dsn = pg_dsn or PG_DSN

    nc = await nats.connect(nats_addr)
    js = nc.jetstream()

    # Ensure OSINT stream exists
    await js.add_stream(
        StreamConfig(
            name="INGEST_OSINT",
            subjects=["ingest.osint.>"],
            retention="limits",
            max_bytes=1_073_741_824,
        )
    )

    cache = redis.from_url(valkey_addr)

    logger.info(
        "OSINT adapter started with %d feeds, NATS=%s",
        len(config.feeds),
        nats_addr,
    )

    try:
        async with httpx.AsyncClient() as client:
            while True:
                tasks = [_process_feed(feed, client, js, cache, dsn) for feed in config.feeds]
                await asyncio.gather(*tasks, return_exceptions=True)

                # Sleep until the shortest interval
                min_interval = min(f.interval for f in config.feeds)
                await asyncio.sleep(min_interval)
    finally:
        await cache.aclose()
        await nc.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(run())
