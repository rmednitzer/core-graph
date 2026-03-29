"""evidence.chain.verify — Audit log hash chain verification.

Reads the audit_log table and verifies the integrity of the hash chain
by recomputing each entry's hash and checking linkage to the previous entry.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import sys
from dataclasses import dataclass
from datetime import datetime

import psycopg
from psycopg.rows import dict_row

from api.config import PG_DSN

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of hash chain verification."""

    total_entries: int
    verified_count: int
    first_broken_link: int | None = None
    verification_timestamp: str = ""


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
        verification_timestamp=datetime.utcnow().isoformat() + "Z",
    )


async def _main() -> None:
    """CLI entry point for hash chain verification."""
    result = await verify_chain()
    print("Audit log hash chain verification")
    print(f"  Total entries:    {result.total_entries}")
    print(f"  Verified:         {result.verified_count}")
    print(f"  First broken:     {result.first_broken_link or 'none'}")
    print(f"  Timestamp:        {result.verification_timestamp}")
    if result.first_broken_link is not None:
        sys.exit(1)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(_main())
