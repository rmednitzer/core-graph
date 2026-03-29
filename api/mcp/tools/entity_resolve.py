"""api.mcp.tools.entity_resolve — Canonical entity lookup."""

from __future__ import annotations

import json
import logging
from typing import Any

import psycopg
from psycopg.rows import dict_row
from pydantic import BaseModel

from ingest.canonical import canonical_key

logger = logging.getLogger(__name__)

PG_DSN = "postgresql://cg_admin:cg_dev_only@localhost:5432/core_graph"

# Map IOC types to AGE vertex labels
IOC_LABEL_MAP: dict[str, str] = {
    "ip": "CanonicalIP",
    "ipv4": "CanonicalIP",
    "ipv6": "CanonicalIP",
    "domain": "CanonicalDomain",
    "person": "CanonicalPerson",
    "organization": "CanonicalOrganization",
}


class EntityResolveInput(BaseModel):
    """Input model for entity_resolve tool."""

    ioc_type: str
    value: str


class EntityResolveResult(BaseModel):
    """Output model for entity_resolve tool."""

    graph_id: int
    label: str
    properties: dict[str, Any]


async def entity_resolve(ioc_type: str, value: str) -> dict[str, Any] | None:
    """Look up a canonical entity by deterministic key.

    Args:
        ioc_type: The type of IOC (ip, domain, etc.).
        value: The IOC value to resolve.

    Returns:
        Vertex properties if found, None otherwise.
    """
    label = IOC_LABEL_MAP.get(ioc_type.lower())
    if label is None:
        raise ValueError(f"Unknown IOC type: {ioc_type}")

    ckey = canonical_key(ioc_type, value)

    async with await psycopg.AsyncConnection.connect(PG_DSN, row_factory=dict_row) as conn:
        await conn.execute("select set_config('app.max_tlp', '2', true)")
        await conn.execute("set search_path = ag_catalog, '$user', public")

        # Query the graph for the canonical entity
        sql = f"""
            select * from ag_catalog.cypher('core_graph', $$
                match (v:{label} {{value: $value}})
                return v
            $$, %s) as (v agtype)
        """
        # NOTE: label is from a controlled allowlist (IOC_LABEL_MAP), not user input

        cursor = await conn.execute(sql, (json.dumps({"value": value}),))
        row = await cursor.fetchone()

        if row is None:
            logger.info("Entity not found: %s/%s (key=%s)", ioc_type, value, ckey[:16])
            return None

        # TODO: log to audit trail
        logger.info("Entity resolved: %s/%s (key=%s)", ioc_type, value, ckey[:16])
        return dict(row)
