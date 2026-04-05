"""Tests for embedding circuit breaker logic.

Tests the pure circuit breaker state machine without requiring
pydantic, psycopg, or other heavy dependencies.
"""

from __future__ import annotations

import sys
import time
from unittest.mock import MagicMock

# Stub heavy dependencies before importing the module under test
for _mod in (
    "pydantic",
    "psycopg",
    "psycopg.rows",
    "psycopg_pool",
    "prometheus_client",
):
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

# Stub api.config and api.db which vector_search imports
if "api.config" not in sys.modules:
    _cfg = MagicMock()
    _cfg.EMBEDDING_PROVIDER = "none"
    _cfg.EMBEDDING_MODEL = "test"
    _cfg.EMBEDDING_URL = "http://localhost"
    _cfg.EMBEDDING_DIMENSIONS = 768
    _cfg.DEFAULT_TLP = 2
    sys.modules["api.config"] = _cfg
if "api.db" not in sys.modules:
    sys.modules["api.db"] = MagicMock()
if "api" not in sys.modules:
    sys.modules["api"] = MagicMock()

import api.mcp.tools.vector_search as vs  # noqa: E402
from api.mcp.tools.vector_search import (  # noqa: E402
    _CIRCUIT_OPEN_THRESHOLD,
    _CIRCUIT_RESET_SECONDS,
    _check_circuit,
    _record_failure,
    _record_success,
)


def _reset_circuit() -> None:
    """Reset circuit breaker state between tests."""
    vs._embedding_failures = 0
    vs._circuit_opened_at = None


class TestCircuitBreaker:
    """Tests for the embedding circuit breaker."""

    def setup_method(self) -> None:
        _reset_circuit()

    def teardown_method(self) -> None:
        _reset_circuit()

    def test_circuit_starts_closed(self) -> None:
        assert _check_circuit() is True

    def test_circuit_stays_closed_below_threshold(self) -> None:
        for _ in range(_CIRCUIT_OPEN_THRESHOLD - 1):
            _record_failure()
        assert _check_circuit() is True

    def test_circuit_opens_at_threshold(self) -> None:
        for _ in range(_CIRCUIT_OPEN_THRESHOLD):
            _record_failure()
        assert _check_circuit() is False

    def test_success_resets_circuit(self) -> None:
        for _ in range(_CIRCUIT_OPEN_THRESHOLD):
            _record_failure()
        assert _check_circuit() is False

        # Simulate time passing to allow half-open
        vs._circuit_opened_at = time.monotonic() - _CIRCUIT_RESET_SECONDS - 1

        # Half-open allows one attempt
        assert _check_circuit() is True

        # Success closes the circuit
        _record_success()
        assert _check_circuit() is True

    def test_failure_after_half_open_reopens(self) -> None:
        for _ in range(_CIRCUIT_OPEN_THRESHOLD):
            _record_failure()

        vs._circuit_opened_at = time.monotonic() - _CIRCUIT_RESET_SECONDS - 1

        # Half-open allows attempt
        assert _check_circuit() is True

        # Another failure re-opens
        _record_failure()
        assert _check_circuit() is False

    def test_circuit_allows_after_reset_timeout(self) -> None:
        for _ in range(_CIRCUIT_OPEN_THRESHOLD):
            _record_failure()
        assert _check_circuit() is False

        vs._circuit_opened_at = time.monotonic() - _CIRCUIT_RESET_SECONDS - 1
        assert _check_circuit() is True

    def test_circuit_blocked_before_reset_timeout(self) -> None:
        for _ in range(_CIRCUIT_OPEN_THRESHOLD):
            _record_failure()

        vs._circuit_opened_at = time.monotonic() - 1  # only 1 second ago
        assert _check_circuit() is False
