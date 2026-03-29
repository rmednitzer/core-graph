"""ingest.resolver.dedup — Entity deduplication via Valkey Bloom filters.

Uses Bloom filter commands (BF.ADD / BF.EXISTS) to efficiently detect
duplicate IOCs without storing every value in memory.
"""

from __future__ import annotations

from typing import Any

import redis

from ingest.canonical import canonical_key


class BloomDedup:
    """Bloom filter-backed deduplication using Valkey/Redis."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        filter_name: str = "cg:ioc:bloom",
        error_rate: float = 0.001,
        capacity: int = 1_000_000,
    ) -> None:
        self._client: redis.Redis[Any] = redis.Redis(host=host, port=port, db=db)
        self._filter_name = filter_name
        self._error_rate = error_rate
        self._capacity = capacity
        self._ensure_filter()

    def _ensure_filter(self) -> None:
        """Create the Bloom filter if it does not already exist."""
        try:
            self._client.execute_command(
                "BF.RESERVE",
                self._filter_name,
                self._error_rate,
                self._capacity,
            )
        except redis.ResponseError:
            # Filter already exists — this is expected and safe to ignore
            pass

    def is_duplicate(self, ioc_type: str, value: str) -> bool:
        """Check if an IOC has been seen before."""
        key = canonical_key(ioc_type, value)
        result = self._client.execute_command("BF.EXISTS", self._filter_name, key)
        return bool(result)

    def mark_seen(self, ioc_type: str, value: str) -> None:
        """Add an IOC to the Bloom filter."""
        key = canonical_key(ioc_type, value)
        self._client.execute_command("BF.ADD", self._filter_name, key)

    def check_and_mark(self, ioc_type: str, value: str) -> bool:
        """Check if duplicate, then mark as seen. Returns True if was duplicate."""
        key = canonical_key(ioc_type, value)
        # BF.ADD returns 0 if item already existed, 1 if newly added
        result = self._client.execute_command("BF.ADD", self._filter_name, key)
        return result == 0
