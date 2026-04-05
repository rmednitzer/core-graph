"""scripts.stamp_merkle_roots — Request RFC 3161 timestamps for Merkle roots.

Queries audit_merkle_roots where rfc3161_token IS NULL, requests a
timestamp for each root hash, and stores the token. Designed to run
as a periodic task outside pg_cron (which cannot make HTTP calls).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging

import psycopg
from psycopg.rows import dict_row

from api.config import PG_DSN, TSA_ENABLED
from evidence.signing.timestamp import request_timestamp

logger = logging.getLogger(__name__)


async def stamp_pending_roots(pg_dsn: str | None = None) -> int:
    """Stamp all Merkle roots that lack an RFC 3161 token.

    Returns:
        Number of roots successfully stamped.
    """
    if not TSA_ENABLED:
        logger.info("TSA disabled (CG_TSA_ENABLED=false), skipping")
        return 0

    dsn = pg_dsn or PG_DSN
    stamped = 0

    async with await psycopg.AsyncConnection.connect(dsn, row_factory=dict_row) as conn:
        cursor = await conn.execute(
            "select id, root_hash from audit_merkle_roots "
            "where rfc3161_token is null order by id asc"
        )
        rows = await cursor.fetchall()

    for row in rows:
        digest = hashlib.sha256(row["root_hash"].encode()).digest()
        token = await request_timestamp(digest)
        if token is None:
            logger.warning("Failed to stamp Merkle root %d", row["id"])
            continue

        async with await psycopg.AsyncConnection.connect(dsn) as conn:
            await conn.execute(
                "update audit_merkle_roots set rfc3161_token = %s where id = %s",
                (token, row["id"]),
            )
            await conn.commit()

        stamped += 1
        logger.info("Stamped Merkle root %d", row["id"])

    return stamped


async def _main() -> None:
    count = await stamp_pending_roots()
    print(f"Stamped {count} Merkle root(s)")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(_main())
