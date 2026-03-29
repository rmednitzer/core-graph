"""api.mcp.tools.entity_resolve — Canonical entity lookup."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from pydantic import BaseModel

from api.config import DEFAULT_TLP
from api.db import get_connection
from ingest.canonical import canonical_key

logger = logging.getLogger(__name__)

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


async def entity_resolve(
    ioc_type: str,
    value: str,
    caller_identity: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Look up a canonical entity by deterministic key.

    Args:
        ioc_type: The type of IOC (ip, domain, etc.).
        value: The IOC value to resolve.
        caller_identity: MCP session context for RLS enforcement.

    Returns:
        Vertex properties if found, None otherwise.
    """
    label = IOC_LABEL_MAP.get(ioc_type.lower())
    if label is None:
        raise ValueError(f"Unknown IOC type: {ioc_type}")

    ckey = canonical_key(ioc_type, value)

    caller = caller_identity or {"max_tlp": DEFAULT_TLP, "allowed_compartments": []}

    async with get_connection(caller) as conn:
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

        # Write audit log entry on successful resolution
        correlation_id = uuid.uuid4()
        await conn.execute(
            """
            insert into audit_log
                (entity_label, operation, actor, correlation_id)
            values (%s, %s, %s, %s)
            """,
            (
                f"{label}:{value}",
                "RESOLVE",
                caller_identity.get("actor", "mcp") if caller_identity else "mcp",
                correlation_id,
            ),
        )
        await conn.commit()

        logger.info("Entity resolved: %s/%s (key=%s)", ioc_type, value, ckey[:16])
        return dict(row)
