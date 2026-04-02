"""api.mcp.tools.stix_lookup — STIX 2.1 object lookup."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from pydantic import BaseModel

from api.config import DEFAULT_TLP
from api.db import get_connection
from api.utils.cypher_safety import validate_label

logger = logging.getLogger(__name__)

# STIX SDO types mapped to AGE vertex labels
STIX_LABEL_MAP: dict[str, str] = {
    "threat-actor": "ThreatActor",
    "campaign": "Campaign",
    "attack-pattern": "AttackPattern",
    "indicator": "Indicator",
    "malware": "Malware",
    "vulnerability": "Vulnerability",
    "tool": "Tool",
}


class StixLookupInput(BaseModel):
    """Input model for stix_lookup tool."""

    stix_type: str
    stix_id: str


class StixLookupResult(BaseModel):
    """Output model for stix_lookup tool."""

    stix_type: str
    stix_id: str
    properties: dict[str, Any]


async def stix_lookup(
    stix_type: str,
    stix_id: str,
    caller_identity: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Query a STIX 2.1 object stored as a graph vertex.

    Args:
        stix_type: STIX type (e.g., 'threat-actor', 'malware').
        stix_id: STIX identifier (e.g., 'threat-actor--uuid').
        caller_identity: MCP session context for RLS enforcement.

    Returns:
        STIX JSON representation if found, None otherwise.
    """
    label = STIX_LABEL_MAP.get(stix_type.lower())
    if label is None:
        raise ValueError(f"Unknown STIX type: {stix_type}")
    label = validate_label(label)

    caller = caller_identity or {"max_tlp": DEFAULT_TLP, "allowed_compartments": []}

    async with get_connection(caller) as conn:
        sql = f"""
            select * from ag_catalog.cypher('core_graph', $$
                match (v:{label} {{stix_id: $stix_id}})
                return v
            $$, %s) as (v agtype)
        """
        # NOTE: label is from a controlled allowlist (STIX_LABEL_MAP), not user input

        cursor = await conn.execute(sql, (json.dumps({"stix_id": stix_id}),))
        row = await cursor.fetchone()

        if row is None:
            logger.info("STIX object not found: %s/%s", stix_type, stix_id)
            return None

        # Write audit log entry
        correlation_id = uuid.uuid4()
        await conn.execute(
            """
            insert into audit_log
                (entity_label, operation, actor, correlation_id)
            values (%s, %s, %s, %s)
            """,
            (
                f"{label}:{stix_id}",
                "LOOKUP",
                caller_identity.get("actor", "mcp") if caller_identity else "mcp",
                correlation_id,
            ),
        )
        await conn.commit()

        logger.info("STIX object found: %s/%s", stix_type, stix_id)
        return dict(row)
