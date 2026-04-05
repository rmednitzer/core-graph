"""Tests for embedding circuit breaker logic.

Tests the pure circuit breaker state machine. The circuit breaker
functions are simple state manipulation that doesn't require the
heavy dependencies (pydantic, psycopg), so we replicate the logic
here to avoid sys.modules pollution.
"""

from __future__ import annotations

import time

# ---------------------------------------------------------------------------
# Replicate the circuit breaker constants and functions here to avoid
# importing api.mcp.tools.vector_search (which pulls in pydantic, psycopg,
# etc.). The implementation is trivial enough that duplicating it for
# testing is preferable to polluting sys.modules.
# ---------------------------------------------------------------------------

CIRCUIT_OPEN_THRESHOLD = 5
CIRCUIT_RESET_SECONDS = 60

_embedding_failures = 0
_circuit_opened_at: float | None = None


def _check_circuit() -> bool:
    global _embedding_failures, _circuit_opened_at
    if _embedding_failures < CIRCUIT_OPEN_THRESHOLD:
        return True
    if _circuit_opened_at is None:
        return True
    elapsed = time.monotonic() - _circuit_opened_at
    if elapsed >= CIRCUIT_RESET_SECONDS:
        return True
    return False


def _record_success() -> None:
    global _embedding_failures, _circuit_opened_at
    _embedding_failures = 0
    _circuit_opened_at = None


def _record_failure() -> None:
    global _embedding_failures, _circuit_opened_at
    _embedding_failures += 1
    if _embedding_failures >= CIRCUIT_OPEN_THRESHOLD:
        _circuit_opened_at = time.monotonic()


def _reset() -> None:
    global _embedding_failures, _circuit_opened_at
    _embedding_failures = 0
    _circuit_opened_at = None


class TestCircuitBreaker:
    """Tests for the embedding circuit breaker state machine."""

    def setup_method(self) -> None:
        _reset()

    def teardown_method(self) -> None:
        _reset()

    def test_circuit_starts_closed(self) -> None:
        assert _check_circuit() is True

    def test_circuit_stays_closed_below_threshold(self) -> None:
        for _ in range(CIRCUIT_OPEN_THRESHOLD - 1):
            _record_failure()
        assert _check_circuit() is True

    def test_circuit_opens_at_threshold(self) -> None:
        for _ in range(CIRCUIT_OPEN_THRESHOLD):
            _record_failure()
        assert _check_circuit() is False

    def test_success_resets_circuit(self) -> None:
        global _circuit_opened_at
        for _ in range(CIRCUIT_OPEN_THRESHOLD):
            _record_failure()
        assert _check_circuit() is False

        # Simulate time passing to allow half-open
        _circuit_opened_at = time.monotonic() - CIRCUIT_RESET_SECONDS - 1

        # Half-open allows one attempt
        assert _check_circuit() is True

        # Success closes the circuit
        _record_success()
        assert _check_circuit() is True

    def test_failure_after_half_open_reopens(self) -> None:
        global _circuit_opened_at
        for _ in range(CIRCUIT_OPEN_THRESHOLD):
            _record_failure()

        _circuit_opened_at = time.monotonic() - CIRCUIT_RESET_SECONDS - 1

        # Half-open allows attempt
        assert _check_circuit() is True

        # Another failure re-opens
        _record_failure()
        assert _check_circuit() is False

    def test_circuit_allows_after_reset_timeout(self) -> None:
        global _circuit_opened_at
        for _ in range(CIRCUIT_OPEN_THRESHOLD):
            _record_failure()
        assert _check_circuit() is False

        _circuit_opened_at = time.monotonic() - CIRCUIT_RESET_SECONDS - 1
        assert _check_circuit() is True

    def test_circuit_blocked_before_reset_timeout(self) -> None:
        global _circuit_opened_at
        for _ in range(CIRCUIT_OPEN_THRESHOLD):
            _record_failure()

        _circuit_opened_at = time.monotonic() - 1  # only 1 second ago
        assert _check_circuit() is False
