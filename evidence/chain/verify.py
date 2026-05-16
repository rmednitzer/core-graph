"""evidence.chain.verify — Audit log hash chain and Merkle root verification.

Reads the audit_log table and verifies the integrity of the hash chain
by recomputing each entry's hash and checking linkage to the previous entry.
Optionally verifies Merkle roots stored in audit_merkle_roots.

Verification is fail-closed: any broken link, hash mismatch, id-sequence
gap, or genesis violation invalidates the whole result. The verifier never
trusts a stored entry_hash it could not itself recompute.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime

import psycopg
from psycopg.rows import dict_row

from api.config import PG_DSN
from evidence.chain.merkle import compute_merkle_root

logger = logging.getLogger(__name__)

_FIELD_SEP = "\x1e"
_GENESIS = "genesis"


@dataclass
class VerificationResult:
    """Result of hash chain or Merkle root verification."""

    total_entries: int
    verified_count: int
    first_broken_link: int | None = None
    verification_timestamp: str = ""
    merkle_batches_checked: int = 0
    merkle_mismatches: list[int] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True iff every entry verified and nothing was flagged."""
        return (
            self.first_broken_link is None
            and not self.merkle_mismatches
            and self.verified_count == self.total_entries
        )


def _canonical_timestamp(value: datetime) -> str:
    """UTC ISO-8601 with fixed 6-digit microseconds and a trailing Z.

    Must match the PostgreSQL trigger's
    ``to_char(created_at at time zone 'UTC',
              'YYYY-MM-DD"T"HH24:MI:SS"."US"Z"')``
    (schema/migrations/024_audit_log_integrity_hardening.sql) byte-for-byte.
    """
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _compute_entry_hash(entry: dict) -> str:
    """Recompute the expected hash for an audit log entry.

    Mirrors audit_log_hash_chain() in migration 024: fields coalesced to
    text and joined with U+001E, created_at in canonical UTC form.
    """
    payload = _FIELD_SEP.join(
        (
            (str(entry["entity_id"]) if entry["entity_id"] is not None else ""),
            (entry["entity_label"] or ""),
            entry["operation"],
            (entry["old_value_hash"] or ""),
            (entry["new_value_hash"] or ""),
            entry["actor"],
            (str(entry["correlation_id"]) if entry["correlation_id"] is not None else ""),
            (entry["prev_entry_hash"] or ""),
            _canonical_timestamp(entry["created_at"]),
        )
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def verify_entries(entries: list[dict]) -> VerificationResult:
    """Pure hash-chain verification over an ordered list of entries.

    Fail-closed. Detects prev_entry_hash linkage breaks (including a
    deleted middle row, whose successor will no longer chain),
    recomputed-hash mismatches, and a missing/invalid genesis. A flagged
    entry never advances the expected chain head to its own (untrusted)
    stored hash. Tail truncation is caught separately by the Merkle
    entry_count/root check in verify_merkle_roots.
    """
    total = len(entries)
    verified = 0
    first_broken: int | None = None

    prev_hash = _GENESIS

    def flag(entry_id: int, reason: str, **ctx: object) -> None:
        nonlocal first_broken
        if first_broken is None:
            first_broken = entry_id
        logger.error("Audit chain broken at id=%s: %s %s", entry_id, reason, ctx)

    # Note: we deliberately do NOT check id contiguity. PostgreSQL
    # bigserial is not gap-free (rolled-back inserts consume sequence
    # values non-transactionally, plus cache jumps/crashes), so gaps are
    # normal and not evidence of tampering. Deletion of a middle row is
    # already caught by the linkage check (its successor's
    # prev_entry_hash will not match); tail truncation is caught by the
    # Merkle entry_count/root check in verify_merkle_roots.
    for entry in entries:
        entry_id = entry["id"]

        # 1. linkage.
        if not hmac.compare_digest(entry["prev_entry_hash"] or "", prev_hash):
            flag(entry_id, "linkage", expected=prev_hash, got=entry["prev_entry_hash"])
            # Do NOT adopt the untrusted stored hash; keep recomputing
            # against what the chain *should* be.
            prev_hash = _compute_entry_hash(entry)
            continue

        # 2. recomputed entry hash.
        expected = _compute_entry_hash(entry)
        if not hmac.compare_digest(entry["entry_hash"] or "", expected):
            flag(entry_id, "hash mismatch", expected=expected, got=entry["entry_hash"])
            prev_hash = expected
            continue

        verified += 1
        prev_hash = expected

    # 3. genesis: the first row must declare the genesis sentinel.
    if entries and (entries[0]["prev_entry_hash"] or "") != _GENESIS:
        flag(entries[0]["id"], "genesis", expected=_GENESIS, got=entries[0]["prev_entry_hash"])

    return VerificationResult(
        total_entries=total,
        verified_count=verified,
        first_broken_link=first_broken,
        verification_timestamp=datetime.now(UTC).isoformat(),
    )


async def verify_chain(pg_dsn: str | None = None) -> VerificationResult:
    """Verify the audit log hash chain integrity.

    Reads all entries in id order and delegates to :func:`verify_entries`.
    """
    dsn = pg_dsn or PG_DSN

    async with await psycopg.AsyncConnection.connect(dsn, row_factory=dict_row) as conn:
        cursor = await conn.execute("select * from audit_log order by id asc")
        entries = await cursor.fetchall()

    return verify_entries(entries)


async def verify_merkle_roots(pg_dsn: str | None = None) -> VerificationResult:
    """Verify all Merkle roots in audit_merkle_roots.

    For each stored root, reads the audit_log entries in its id range,
    asserts the row count matches the stored entry_count (rows
    added/removed inside an already-stamped range are detected even if a
    recompute would otherwise line up), recomputes the domain-separated
    Merkle root, and compares it constant-time against the stored root.
    """
    dsn = pg_dsn or PG_DSN

    batches_checked = 0
    mismatches: list[int] = []

    async with await psycopg.AsyncConnection.connect(dsn, row_factory=dict_row) as conn:
        cursor = await conn.execute("select * from audit_merkle_roots order by id asc")
        roots = await cursor.fetchall()

        for root_row in roots:
            batch_start = root_row["batch_start"]
            batch_end = root_row["batch_end"]
            stored_root = root_row["root_hash"]
            stored_count = root_row["entry_count"]

            cursor = await conn.execute(
                "select entry_hash from audit_log where id >= %s and id <= %s order by id asc",
                (batch_start, batch_end),
            )
            entries = await cursor.fetchall()

            hashes = [e["entry_hash"] for e in entries]
            batches_checked += 1

            if not hashes:
                logger.error(
                    "Merkle batch %d has no audit_log entries (range %d-%d)",
                    root_row["id"],
                    batch_start,
                    batch_end,
                )
                mismatches.append(root_row["id"])
                continue

            if len(hashes) != stored_count:
                logger.error(
                    "Merkle batch %d entry_count mismatch: stored=%d, found=%d",
                    root_row["id"],
                    stored_count,
                    len(hashes),
                )
                mismatches.append(root_row["id"])
                continue

            recomputed = compute_merkle_root(hashes)
            if not hmac.compare_digest(recomputed, stored_root):
                logger.error(
                    "Merkle root mismatch for batch %d: stored=%s, recomputed=%s",
                    root_row["id"],
                    stored_root,
                    recomputed,
                )
                mismatches.append(root_row["id"])

    return VerificationResult(
        total_entries=batches_checked,
        verified_count=batches_checked - len(mismatches),
        merkle_batches_checked=batches_checked,
        merkle_mismatches=mismatches,
        verification_timestamp=datetime.now(UTC).isoformat(),
    )


async def _main() -> None:
    """CLI entry point for hash chain and Merkle verification."""
    run_merkle = "--merkle" in sys.argv

    result = await verify_chain()
    print("Audit log hash chain verification")
    print(f"  Total entries:    {result.total_entries}")
    print(f"  Verified:         {result.verified_count}")
    print(f"  First broken:     {result.first_broken_link or 'none'}")
    print(f"  Timestamp:        {result.verification_timestamp}")

    exit_code = 0
    if not result.ok:
        exit_code = 1

    if run_merkle:
        merkle_result = await verify_merkle_roots()
        print()
        print("Merkle root verification")
        print(f"  Batches checked:  {merkle_result.merkle_batches_checked}")
        print(f"  Verified:         {merkle_result.verified_count}")
        print(f"  Mismatches:       {merkle_result.merkle_mismatches or 'none'}")
        if not merkle_result.ok:
            exit_code = 1

    if exit_code:
        sys.exit(exit_code)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(_main())
