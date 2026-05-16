"""Hash-chain verifier: canonical encoding + fail-closed semantics.

These tests pin the exact payload format that
schema/migrations/024_audit_log_integrity_hardening.sql must reproduce in
SQL, and assert that verification is fail-closed (the live-DB round trip
is exercised by tests/schema/test_migrations.sh in CI).
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta, timezone

from evidence.chain.verify import (
    _canonical_timestamp,
    _compute_entry_hash,
    verify_entries,
)


def _entry(eid: int, prev_hash: str, **over: object) -> dict:
    e = {
        "id": eid,
        "entity_id": 42,
        "entity_label": "ThreatActor",
        "operation": "INSERT",
        "old_value_hash": None,
        "new_value_hash": "ab" * 32,
        "actor": "svc:graph_writer",
        "correlation_id": None,
        "prev_entry_hash": prev_hash,
        "created_at": datetime(2026, 5, 16, 12, 34, 56, 123456, tzinfo=UTC),
    }
    e.update(over)
    e["entry_hash"] = _compute_entry_hash(e)
    return e


def test_canonical_timestamp_is_utc_microsecond_z() -> None:
    dt = datetime(2026, 5, 16, 12, 34, 56, 123456, tzinfo=UTC)
    assert _canonical_timestamp(dt) == "2026-05-16T12:34:56.123456Z"
    # Sub-second zero still renders 6 digits (matches PG to_char US).
    assert _canonical_timestamp(dt.replace(microsecond=0)) == "2026-05-16T12:34:56.000000Z"
    # Non-UTC input is normalised to UTC before formatting.
    plus2 = dt.astimezone(timezone(timedelta(hours=2)))
    assert _canonical_timestamp(plus2) == "2026-05-16T12:34:56.123456Z"


def test_payload_format_matches_documented_sql_framing() -> None:
    e = _entry(1, "genesis")
    expected_payload = "\x1e".join(
        (
            "42",
            "ThreatActor",
            "INSERT",
            "",
            "ab" * 32,
            "svc:graph_writer",
            "",
            "genesis",
            "2026-05-16T12:34:56.123456Z",
        )
    )
    assert e["entry_hash"] == hashlib.sha256(expected_payload.encode()).hexdigest()


def test_valid_chain_verifies() -> None:
    e1 = _entry(1, "genesis")
    e2 = _entry(2, e1["entry_hash"], entity_id=43)
    e3 = _entry(3, e2["entry_hash"], entity_id=44)
    result = verify_entries([e1, e2, e3])
    assert result.ok
    assert result.verified_count == 3
    assert result.first_broken_link is None


def test_tampered_entry_fails_closed() -> None:
    e1 = _entry(1, "genesis")
    e2 = _entry(2, e1["entry_hash"])
    e2["entity_label"] = "Indicator"  # mutate after hash computed
    result = verify_entries([e1, e2])
    assert not result.ok
    assert result.first_broken_link == 2


def test_mid_row_deletion_detected_via_linkage() -> None:
    """A deleted middle row is caught by the chain (its successor's
    prev_entry_hash no longer matches) — without needing an id-gap
    heuristic."""
    e1 = _entry(1, "genesis")
    e2 = _entry(2, e1["entry_hash"])
    e3 = _entry(3, e2["entry_hash"])  # legitimately chains off e2
    # e2 physically removed (restore/PITR/raw edit); e3 still points at
    # the original e2 hash, which no longer follows e1.
    result = verify_entries([e1, e3])
    assert not result.ok
    assert result.first_broken_link == 3


def test_legitimate_sequence_gap_is_not_flagged() -> None:
    """PostgreSQL bigserial is not gap-free (rolled-back inserts, cache
    jumps). Non-contiguous ids with correct linkage must verify cleanly —
    no false positives."""
    e1 = _entry(1, "genesis")
    e2 = _entry(2, e1["entry_hash"])
    e5 = _entry(5, e2["entry_hash"])  # ids 3,4 burned by rolled-back tx
    result = verify_entries([e1, e2, e5])
    assert result.ok
    assert result.verified_count == 3
    assert result.first_broken_link is None


def test_missing_genesis_detected() -> None:
    e1 = _entry(1, "not-genesis")
    result = verify_entries([e1])
    assert not result.ok


def test_tamper_propagates_no_silent_resync() -> None:
    """A mutated row (entry_hash NOT recomputed — UPDATE is DB-blocked, so
    this models a raw-table/restore edit) must flag that row AND every
    downstream row. The verifier must not adopt the untrusted stored hash
    and silently resync to the tampered chain.

    (A fully offline-recomputed self-consistent chain is, by hash-chain
    math, indistinguishable from a genuine one — that case is defended by
    the externally anchored Merkle root / RFC 3161 token, not by this
    verifier.)
    """
    e1 = _entry(1, "genesis")
    e2 = _entry(2, e1["entry_hash"])
    e3 = _entry(3, e2["entry_hash"])  # legitimately chains off original e2
    e2["actor"] = "attacker"  # mutate content; stored entry_hash now stale

    result = verify_entries([e1, e2, e3])
    assert not result.ok
    assert result.first_broken_link == 2
    assert result.verified_count == 1  # only e1; tamper propagated to e3
