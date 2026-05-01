"""Tests for the distributed circuit breaker.

Exercises both the Valkey-backed code path (with an in-memory async stub)
and the local-fallback path (when Valkey is None or raises).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from api.utils.circuit_breaker import CircuitBreaker


class _FakeValkey:
    """Minimal in-memory async stand-in for redis.asyncio."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.expires: dict[str, float] = {}

    async def incr(self, key: str) -> int:
        self._evict()
        cur = int(self.store.get(key, "0")) + 1
        self.store[key] = str(cur)
        return cur

    async def expire(self, key: str, seconds: int) -> bool:
        self.expires[key] = time.time() + seconds
        return True

    async def get(self, key: str) -> str | None:
        self._evict()
        return self.store.get(key)

    async def set(
        self,
        key: str,
        value: str,
        *,
        nx: bool = False,
        ex: int | None = None,
    ) -> bool:
        self._evict()
        if nx and key in self.store:
            return False
        self.store[key] = value
        if ex is not None:
            self.expires[key] = time.time() + ex
        return True

    async def delete(self, *keys: str) -> int:
        n = 0
        for k in keys:
            if k in self.store:
                del self.store[k]
                n += 1
            self.expires.pop(k, None)
        return n

    def _evict(self) -> None:
        now = time.time()
        for k, exp in list(self.expires.items()):
            if exp <= now:
                self.store.pop(k, None)
                self.expires.pop(k, None)


class _FlakyValkey(_FakeValkey):
    """Always raises — used to verify the local-fallback path."""

    async def incr(self, key: str) -> int:
        raise RuntimeError("valkey unreachable")

    async def get(self, key: str) -> str | None:
        raise RuntimeError("valkey unreachable")

    async def set(self, key: str, value: str, **kw: Any) -> bool:
        raise RuntimeError("valkey unreachable")

    async def delete(self, *keys: str) -> int:
        raise RuntimeError("valkey unreachable")

    async def expire(self, key: str, seconds: int) -> bool:
        raise RuntimeError("valkey unreachable")


@pytest.mark.asyncio
async def test_starts_closed() -> None:
    cb = CircuitBreaker(key="cg:cb:test", valkey=_FakeValkey())
    assert await cb.allow() is True
    assert await cb.state() == "closed"


@pytest.mark.asyncio
async def test_opens_after_threshold_failures_valkey() -> None:
    cb = CircuitBreaker(
        key="cg:cb:test",
        threshold=3,
        window_seconds=10,
        reset_seconds=10,
        valkey=_FakeValkey(),
    )
    for _ in range(3):
        await cb.record_failure()
    assert await cb.state() == "open"
    assert await cb.allow() is False


@pytest.mark.asyncio
async def test_half_open_after_reset_window() -> None:
    fake = _FakeValkey()
    cb = CircuitBreaker(
        key="cg:cb:test",
        threshold=2,
        window_seconds=60,
        reset_seconds=1,
        valkey=fake,
    )
    await cb.record_failure()
    await cb.record_failure()
    assert await cb.allow() is False

    # Hand-roll the marker far enough into the past to enter half-open.
    fake.store[cb._opened_at_key] = str(time.time() - 5)

    assert await cb.state() == "half_open"
    assert await cb.allow() is True


@pytest.mark.asyncio
async def test_success_resets_state() -> None:
    cb = CircuitBreaker(
        key="cg:cb:test",
        threshold=2,
        valkey=_FakeValkey(),
    )
    await cb.record_failure()
    await cb.record_failure()
    assert await cb.state() == "open"
    await cb.record_success()
    assert await cb.state() == "closed"


@pytest.mark.asyncio
async def test_local_fallback_on_valkey_failure() -> None:
    cb = CircuitBreaker(
        key="cg:cb:test",
        threshold=3,
        valkey=_FlakyValkey(),
    )
    for _ in range(3):
        await cb.record_failure()
    # Even with a broken Valkey the local fallback opens the breaker.
    assert await cb.state() == "open"
    assert await cb.allow() is False


@pytest.mark.asyncio
async def test_local_only_breaker_no_valkey() -> None:
    cb = CircuitBreaker(key="cg:cb:test", threshold=2, valkey=None)
    assert await cb.allow() is True
    await cb.record_failure()
    await cb.record_failure()
    assert await cb.allow() is False


@pytest.mark.asyncio
async def test_concurrent_failures_share_valkey_state() -> None:
    fake = _FakeValkey()
    cb_a = CircuitBreaker(key="cg:cb:shared", threshold=4, valkey=fake)
    cb_b = CircuitBreaker(key="cg:cb:shared", threshold=4, valkey=fake)

    await asyncio.gather(
        cb_a.record_failure(),
        cb_a.record_failure(),
        cb_b.record_failure(),
        cb_b.record_failure(),
    )
    # Both instances see the breaker as open via the shared Valkey state.
    assert await cb_a.state() == "open"
    assert await cb_b.state() == "open"
