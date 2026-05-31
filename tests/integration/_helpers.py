"""Shared helpers for the integration suite.

Kept in a plain module (not ``conftest``) so tests can import it without
importing the conftest under its dotted name — which would make pytest register
the conftest twice (path name + module name) and abort collection.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import psycopg


async def poll_cypher(
    conn: psycopg.AsyncConnection,
    cypher: str,
    *,
    timeout: float = 10.0,
    interval: float = 0.2,
) -> list[Any]:
    """Poll an AGE read query until it returns ≥1 row or the timeout elapses.

    The connection must be autocommit so each attempt sees freshly committed
    writes from the background graph writer.
    """
    deadline = time.monotonic() + timeout
    while True:
        cur = await conn.execute(cypher)
        rows = await cur.fetchall()
        if rows:
            return rows
        if time.monotonic() >= deadline:
            return rows
        await asyncio.sleep(interval)


async def poll_query(
    conn: psycopg.AsyncConnection,
    sql: str,
    params: tuple = (),
    *,
    timeout: float = 8.0,
    interval: float = 0.2,
) -> Any:
    """Poll a relational query until it returns a row or the timeout elapses."""
    deadline = time.monotonic() + timeout
    while True:
        cur = await conn.execute(sql, params)
        row = await cur.fetchone()
        if row:
            return row
        if time.monotonic() >= deadline:
            return row
        await asyncio.sleep(interval)
