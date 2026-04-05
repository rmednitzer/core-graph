"""Tests for DLQ error classification."""

from __future__ import annotations


def _classify(msg: str) -> str:
    """Import and call classify_error, handling missing nats dependency."""
    # classify_error is pure logic, import it directly to avoid nats import
    import sys
    from unittest.mock import MagicMock

    # Stub out nats and psycopg if not available
    for mod_name in ("nats", "nats.js", "nats.js.api", "psycopg", "psycopg.rows"):
        if mod_name not in sys.modules:
            sys.modules[mod_name] = MagicMock()

    # Also stub ingest.metrics if prometheus_client is missing
    if "ingest.metrics" not in sys.modules:
        mock_metrics = MagicMock()
        sys.modules["ingest.metrics"] = mock_metrics

    from ingest.dlq.processor import classify_error

    return classify_error(msg)


class TestClassifyError:
    """Tests for classify_error function."""

    def test_schema_mismatch_validation(self) -> None:
        assert _classify("JSON validation failed: missing field 'type'") == "schema_mismatch"

    def test_schema_mismatch_invalid(self) -> None:
        assert _classify("Invalid STIX object format") == "schema_mismatch"

    def test_schema_mismatch_schema(self) -> None:
        assert _classify("Schema error in payload") == "schema_mismatch"

    def test_connection_error_refused(self) -> None:
        assert _classify("Connection refused to PostgreSQL") == "connection_error"

    def test_connection_error_unreachable(self) -> None:
        assert _classify("Host unreachable: 10.0.0.5") == "connection_error"

    def test_connection_error_dns(self) -> None:
        assert _classify("DNS resolution failed for nats.svc.cluster.local") == "connection_error"

    def test_constraint_violation_unique(self) -> None:
        assert _classify("unique constraint violated on stix_id") == "constraint_violation"

    def test_constraint_violation_duplicate(self) -> None:
        assert _classify("duplicate key value violates constraint") == "constraint_violation"

    def test_constraint_violation_foreign_key(self) -> None:
        assert _classify("foreign key constraint failed") == "constraint_violation"

    def test_timeout(self) -> None:
        assert _classify("Query timed out after 30s") == "timeout"

    def test_timeout_deadline(self) -> None:
        assert _classify("Deadline exceeded for operation") == "timeout"

    def test_authorization_forbidden(self) -> None:
        assert _classify("403 Forbidden: insufficient TLP clearance") == "authorization"

    def test_authorization_denied(self) -> None:
        assert _classify("Permission denied for user cg_analyst") == "authorization"

    def test_authorization_401(self) -> None:
        assert _classify("HTTP 401 from upstream service") == "authorization"

    def test_unknown_generic(self) -> None:
        assert _classify("Something unexpected happened") == "unknown"

    def test_unknown_empty(self) -> None:
        assert _classify("") == "unknown"

    def test_case_insensitive(self) -> None:
        assert _classify("CONNECTION REFUSED") == "connection_error"
        assert _classify("TIMEOUT exceeded") == "timeout"
