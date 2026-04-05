"""evidence.chain.verify — Audit log hash chain and Merkle root verification.

Reads the audit_log table and verifies the integrity of the hash chain
by recomputing each entry's hash and checking linkage to the previous entry.
Optionally verifies Merkle roots stored in audit_merkle_roots.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime

import psycopg
from psycopg.rows import dict_row

from api.config import PG_DSN
from evidence.chain.merkle import compute_merkle_root

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of hash chain or Merkle root verification."""

    total_entries: int
    verified_count: int
    first_broken_link: int | None = None
    verification_timestamp: str = ""
    merkle_batches_checked: int = 0
    merkle_mismatches: list[int] = field(default_factory=list)


def _compute_entry_hash(entry: dict) -> str:
    """Recompute the expected hash for an audit log entry.

    Mirrors the PostgreSQL trigger function audit_log_hash_chain().
    """
    payload = (
        (str(entry["entity_id"]) if entry["entity_id"] is not None else "")
        + (entry["entity_label"] or "")
        + entry["operation"]
        + (entry["old_value_hash"] or "")
        + (entry["new_value_hash"] or "")
        + entry["actor"]
        + (str(entry["correlation_id"]) if entry["correlation_id"] is not None else "")
        + (entry["prev_entry_hash"] or "")
        + str(entry["created_at"])
    )
    return hashlib.sha256(payload.encode()).hexdigest()


async def verify_chain(pg_dsn: str | None = None) -> VerificationResult:
    """Verify the audit log hash chain integrity.

    Reads all entries in order, recomputes each hash, and checks
    that prev_entry_hash links correctly to the preceding entry.

    Args:
        pg_dsn: PostgreSQL connection string. Defaults to CG_PG_DSN.

    Returns:
        VerificationResult with counts and first broken link if any.
    """
    dsn = pg_dsn or PG_DSN

    async with await psycopg.AsyncConnection.connect(dsn, row_factory=dict_row) as conn:
        cursor = await conn.execute("select * from audit_log order by id asc")
        entries = await cursor.fetchall()

    total = len(entries)
    verified = 0
    first_broken: int | None = None

    prev_hash = "genesis"

    for entry in entries:
        # Check prev_entry_hash linkage
        if entry["prev_entry_hash"] != prev_hash:
            if first_broken is None:
                first_broken = entry["id"]
                logger.error(
                    "Broken chain at id=%d: expected prev_hash=%s, got=%s",
                    entry["id"],
                    prev_hash,
                    entry["prev_entry_hash"],
                )
            prev_hash = entry["entry_hash"]
            continue

        # Recompute and verify entry hash
        expected_hash = _compute_entry_hash(entry)
        if entry["entry_hash"] != expected_hash:
            if first_broken is None:
                first_broken = entry["id"]
                logger.error(
                    "Hash mismatch at id=%d: expected=%s, stored=%s",
                    entry["id"],
                    expected_hash,
                    entry["entry_hash"],
                )
            prev_hash = entry["entry_hash"]
            continue

        verified += 1
        prev_hash = entry["entry_hash"]

    return VerificationResult(
        total_entries=total,
        verified_count=verified,
        first_broken_link=first_broken,
        verification_timestamp=datetime.now(UTC).isoformat(),
    )


async def verify_merkle_roots(pg_dsn: str | None = None) -> VerificationResult:
    """Verify all Merkle roots in audit_merkle_roots.

    For each stored Merkle root, reads the corresponding audit_log entries
    by ID range, recomputes the Merkle root from their entry_hash values,
    and compares against the stored root_hash.

    Args:
        pg_dsn: PostgreSQL connection string. Defaults to CG_PG_DSN.

    Returns:
        VerificationResult with Merkle-specific fields populated.
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

            cursor = await conn.execute(
                "select entry_hash from audit_log where id >= %s and id <= %s order by id asc",
                (batch_start, batch_end),
            )
            entries = await cursor.fetchall()

            hashes = [e["entry_hash"] for e in entries]
            if not hashes:
                logger.warning(
                    "Merkle batch %d has no audit_log entries (range %d-%d)",
                    root_row["id"],
                    batch_start,
                    batch_end,
                )
                mismatches.append(root_row["id"])
                batches_checked += 1
                continue

            recomputed = compute_merkle_root(hashes)
            if recomputed != stored_root:
                logger.error(
                    "Merkle root mismatch for batch %d: stored=%s, recomputed=%s",
                    root_row["id"],
                    stored_root,
                    recomputed,
                )
                mismatches.append(root_row["id"])

            batches_checked += 1

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
    if result.first_broken_link is not None:
        exit_code = 1

    if run_merkle:
        merkle_result = await verify_merkle_roots()
        print()
        print("Merkle root verification")
        print(f"  Batches checked:  {merkle_result.merkle_batches_checked}")
        print(f"  Verified:         {merkle_result.verified_count}")
        print(f"  Mismatches:       {merkle_result.merkle_mismatches or 'none'}")
        if merkle_result.merkle_mismatches:
            exit_code = 1

    if exit_code:
        sys.exit(exit_code)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(_main())
