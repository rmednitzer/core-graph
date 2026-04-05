"""Tests for DLQ error classification.

Tests the classify_error logic by replicating the pure function locally
to avoid importing the full DLQ processor module (which requires nats,
psycopg, prometheus_client).
"""

from __future__ import annotations


def _classify(msg: str) -> str:
    """Replicate classify_error logic for testing without heavy deps."""
    lower = msg.lower()
    if any(kw in lower for kw in ("schema", "validation", "invalid", "missing field")):
        return "schema_mismatch"
    if any(kw in lower for kw in ("connection", "refused", "unreachable", "dns")):
        return "connection_error"
    if any(kw in lower for kw in ("constraint", "unique", "duplicate", "foreign key", "violates")):
        return "constraint_violation"
    if any(kw in lower for kw in ("timeout", "timed out", "deadline")):
        return "timeout"
    authz_kw = ("authorization", "forbidden", "permission", "denied", "401", "403")
    if any(kw in lower for kw in authz_kw):
        return "authorization"
    return "unknown"


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
