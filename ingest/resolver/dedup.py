"""ingest.resolver.dedup — Entity deduplication via Valkey Bloom filters.

Uses Bloom filter commands (BF.ADD / BF.EXISTS) to efficiently detect
duplicate IOCs without storing every value in memory.
"""

from __future__ import annotations

import redis.asyncio as redis
from redis.exceptions import ResponseError

from ingest.canonical import canonical_key


class BloomDedup:
    """Bloom filter-backed deduplication using Valkey/Redis.

    Uses the async redis client so callers from the ingest pipeline do
    not block the event loop on BF.* commands.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        filter_name: str = "cg:ioc:bloom",
        error_rate: float = 0.001,
        capacity: int = 1_000_000,
    ) -> None:
        self._client: redis.Redis = redis.Redis(host=host, port=port, db=db)
        self._filter_name = filter_name
        self._error_rate = error_rate
        self._capacity = capacity
        self._filter_ready = False

    async def _ensure_filter(self) -> None:
        """Create the Bloom filter if it does not already exist."""
        if self._filter_ready:
            return
        try:
            await self._client.execute_command(
                "BF.RESERVE",
                self._filter_name,
                self._error_rate,
                self._capacity,
            )
        except ResponseError as exc:
            # Only the "item exists" error means the filter is already
            # created — anything else (e.g. RedisBloom module not loaded,
            # BF.RESERVE unknown command) is a real misconfiguration and
            # must propagate so we don't mark the filter ready falsely.
            if "exists" not in str(exc).lower():
                raise
        self._filter_ready = True

    async def is_duplicate(self, ioc_type: str, value: str) -> bool:
        """Check if an IOC has been seen before."""
        await self._ensure_filter()
        key = canonical_key(ioc_type, value)
        result = await self._client.execute_command("BF.EXISTS", self._filter_name, key)
        return bool(result)

    async def mark_seen(self, ioc_type: str, value: str) -> None:
        """Add an IOC to the Bloom filter."""
        await self._ensure_filter()
        key = canonical_key(ioc_type, value)
        await self._client.execute_command("BF.ADD", self._filter_name, key)

    async def check_and_mark(self, ioc_type: str, value: str) -> bool:
        """Check if duplicate, then mark as seen. Returns True if was duplicate."""
        await self._ensure_filter()
        key = canonical_key(ioc_type, value)
        # BF.ADD returns 0 if item already existed, 1 if newly added
        result = await self._client.execute_command("BF.ADD", self._filter_name, key)
        return result == 0

    async def aclose(self) -> None:
        """Close the underlying Redis connection."""
        await self._client.aclose()
