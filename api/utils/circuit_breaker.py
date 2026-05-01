"""api.utils.circuit_breaker — Valkey-backed distributed circuit breaker.

Replaces the per-process breaker that lived in api.mcp.tools.vector_search.
The state is keyed `cg:cb:embedding:<model_id>` so multiple workers share the
same view of failures. If Valkey is unreachable the breaker falls back to a
process-local counter and emits a WARN log.

Semantics (per (key, threshold, window, reset)):
  * Closed: allow requests; record_success resets the counter.
  * Open: when failures >= threshold inside `window_seconds`, set an
    `opened_at` marker. Subsequent checks reject until `reset_seconds` after
    `opened_at`.
  * Half-open: a single attempt is allowed once `reset_seconds` has elapsed.
    A success closes the breaker; a failure re-opens it.

The breaker uses Valkey atomic INCR + EXPIRE. The `opened_at` marker is a
separate key so reads in the half-open window cost only a GET.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class _LocalState:
    failures: int = 0
    opened_at: float | None = None


@dataclass
class CircuitBreaker:
    """Distributed circuit breaker with a process-local fallback.

    Args:
        key: Stable identifier (e.g. `cg:cb:embedding:nomic-embed-text`).
        threshold: Failures inside `window_seconds` that open the breaker.
        window_seconds: Sliding window for failure counting.
        reset_seconds: Time after `opened_at` before a half-open attempt.
        valkey: Optional async Valkey/Redis client. Pass None to skip.
    """

    key: str
    threshold: int = 5
    window_seconds: int = 60
    reset_seconds: int = 60
    valkey: Any | None = None
    _local: _LocalState = field(default_factory=_LocalState)

    @property
    def _failures_key(self) -> str:
        return f"{self.key}:failures"

    @property
    def _opened_at_key(self) -> str:
        return f"{self.key}:opened_at"

    async def allow(self) -> bool:
        """Return True iff the breaker permits a request right now."""
        opened_at = await self._opened_at()
        if opened_at is None:
            return True
        elapsed = time.time() - opened_at
        if elapsed >= self.reset_seconds:
            return True
        return False

    async def record_success(self) -> None:
        """Reset failure count and clear the open marker."""
        self._local = _LocalState()
        if self.valkey is None:
            return
        try:
            await self.valkey.delete(self._failures_key, self._opened_at_key)
        except Exception:
            logger.warning(
                "Valkey unreachable on record_success for %s; using local state",
                self.key,
                exc_info=True,
            )

    async def record_failure(self) -> None:
        """Increment failures and open the breaker if threshold reached."""
        if self.valkey is not None:
            try:
                count = await self.valkey.incr(self._failures_key)
                # Keep the failure window bounded; subsequent INCRs reset the TTL.
                await self.valkey.expire(self._failures_key, self.window_seconds)
                if count >= self.threshold:
                    # SET NX so the *first* failure to cross threshold sets the marker.
                    set_ok = await self.valkey.set(
                        self._opened_at_key,
                        str(time.time()),
                        nx=True,
                        ex=self.reset_seconds + self.window_seconds,
                    )
                    if set_ok:
                        logger.warning(
                            "Circuit breaker %s opened after %d failures",
                            self.key,
                            count,
                        )
                return
            except Exception:
                logger.warning(
                    "Valkey unreachable on record_failure for %s; using local state",
                    self.key,
                    exc_info=True,
                )

        # Local fallback path.
        self._local.failures += 1
        if self._local.failures >= self.threshold and self._local.opened_at is None:
            self._local.opened_at = time.time()
            logger.warning(
                "Circuit breaker %s opened after %d failures (local-fallback)",
                self.key,
                self._local.failures,
            )

    async def state(self) -> str:
        """Return one of {'closed', 'half_open', 'open'} for observability."""
        opened_at = await self._opened_at()
        if opened_at is None:
            return "closed"
        if (time.time() - opened_at) >= self.reset_seconds:
            return "half_open"
        return "open"

    async def _opened_at(self) -> float | None:
        if self.valkey is not None:
            try:
                raw = await self.valkey.get(self._opened_at_key)
                if raw is None:
                    return self._local.opened_at
                return float(raw if isinstance(raw, str) else raw.decode())
            except Exception:
                logger.warning(
                    "Valkey unreachable on get for %s; using local state",
                    self.key,
                    exc_info=True,
                )
        return self._local.opened_at
