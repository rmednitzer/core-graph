"""ingest.connectors.base — Shared base class for all ingest adapters.

Provides a standard interface for fetch/map/publish with built-in
NATS publishing, Valkey delta-sync caching, audit log writing,
and Prometheus metric emission.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import nats
import psycopg
import redis.asyncio as redis
from nats.js.api import StreamConfig
from psycopg.rows import dict_row

from api.config import NATS_URL, PG_DSN, VALKEY_URL
from ingest.metrics import adapter_entities_total, adapter_fetch_total

logger = logging.getLogger(__name__)


@dataclass
class AdapterConfig:
    """Base configuration for all adapters."""

    name: str
    nats_subject: str
    nats_stream: str
    poll_interval: int  # seconds, 0 = event-driven
    default_tlp: int
    delta_sync: bool


class AdapterBase(ABC):
    """Base class for all core-graph ingest adapters.

    Subclasses implement fetch() and map(). The base class provides
    the poll loop, NATS publishing, delta-sync caching, audit logging,
    and metric emission.
    """

    def __init__(self, config: AdapterConfig) -> None:
        self.config = config
        self._nc: nats.NATS | None = None
        self._js: nats.js.JetStreamContext | None = None
        self._cache: redis.Redis | None = None
        self._logger = logging.getLogger(f"adapter.{config.name}")

    @abstractmethod
    async def fetch(self, since: str | None) -> list[dict[str, Any]]:
        """Fetch entities from the source since the given timestamp."""
        ...

    @abstractmethod
    def map(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        """Map a raw source record to a graph entity payload.

        Return None to skip the record.
        """
        ...

    async def run(
        self,
        nats_url: str | None = None,
        valkey_url: str | None = None,
        pg_dsn: str | None = None,
    ) -> None:
        """Main poll loop: fetch → map → publish → audit → sleep."""
        nats_addr = nats_url or NATS_URL
        valkey_addr = valkey_url or VALKEY_URL
        dsn = pg_dsn or PG_DSN

        self._nc = await nats.connect(nats_addr)
        self._js = self._nc.jetstream()
        self._cache = redis.from_url(valkey_addr)

        await self._ensure_stream()

        self._logger.info(
            "Adapter %s started, subject=%s, interval=%ds",
            self.config.name,
            self.config.nats_subject,
            self.config.poll_interval,
        )

        try:
            while True:
                since = await self._get_cached_timestamp() if self.config.delta_sync else None
                try:
                    raw_objects = await self.fetch(since)
                    adapter_fetch_total.labels(
                        adapter=self.config.name, status="success"
                    ).inc()
                except Exception:
                    adapter_fetch_total.labels(
                        adapter=self.config.name, status="error"
                    ).inc()
                    self._logger.exception("Fetch failed for %s", self.config.name)
                    await asyncio.sleep(self.config.poll_interval or 60)
                    continue

                count = 0
                errors = 0
                for raw in raw_objects:
                    entity = self.map(raw)
                    if entity is None:
                        continue
                    try:
                        await self._publish(entity)
                        label = entity.get("label", "unknown")
                        adapter_entities_total.labels(
                            adapter=self.config.name, label=label
                        ).inc()
                        count += 1
                    except Exception:
                        errors += 1
                        self._logger.warning(
                            "Publish failed for entity", exc_info=True
                        )

                if count > 0:
                    await self._cache_timestamp()
                    await self._audit(count, dsn)

                # Hook for subclasses to publish additional data (e.g. relationships)
                await self._post_cycle_hook(count, errors)

                self._logger.info(
                    "%s sync: published=%d errors=%d",
                    self.config.name,
                    count,
                    errors,
                )

                if self.config.poll_interval <= 0:
                    break  # Event-driven adapters don't loop
                await asyncio.sleep(self.config.poll_interval)
        finally:
            if self._cache:
                await self._cache.aclose()
            if self._nc:
                await self._nc.close()

    async def _ensure_stream(self) -> None:
        """Ensure the NATS JetStream stream exists."""
        if self._js is None:
            return
        await self._js.add_stream(
            StreamConfig(
                name=self.config.nats_stream,
                subjects=["enriched.entity.>", "enriched.relationship.>"],
                retention="work_queue",
                max_bytes=1_073_741_824,
            )
        )

    async def _publish(self, entity: dict[str, Any]) -> None:
        """Publish an entity payload to NATS JetStream."""
        if self._js is None:
            raise RuntimeError("JetStream not initialised")
        await self._js.publish(
            self.config.nats_subject,
            json.dumps(entity, default=str).encode(),
        )

    async def _audit(self, count: int, pg_dsn: str) -> None:
        """Write a sync cycle audit log entry."""
        try:
            async with await psycopg.AsyncConnection.connect(pg_dsn, row_factory=dict_row) as conn:
                await conn.execute(
                    """
                    insert into audit_log
                        (entity_label, operation, actor, correlation_id)
                    values (%s, %s, %s, %s)
                    """,
                    (
                        f"{self.config.name}:sync",
                        "SYNC",
                        f"{self.config.name}_adapter",
                        uuid.uuid4(),
                    ),
                )
                await conn.commit()
        except Exception:
            self._logger.warning("Failed to write audit entry", exc_info=True)

    async def _post_cycle_hook(self, count: int, errors: int) -> None:
        """Hook called after each fetch/map/publish cycle.

        Subclasses can override to publish additional data such as
        relationship payloads.  Default implementation is a no-op.
        """

    async def _get_cached_timestamp(self) -> str | None:
        """Get the last sync timestamp from Valkey."""
        if self._cache is None:
            return None
        cache_key = f"{self.config.name}:sync:last_modified"
        value = await self._cache.get(cache_key)
        return value.decode() if value else None

    async def _cache_timestamp(self) -> None:
        """Store the current timestamp in Valkey for delta sync."""
        if self._cache is None:
            return
        cache_key = f"{self.config.name}:sync:last_modified"
        await self._cache.set(cache_key, datetime.now(UTC).isoformat())
