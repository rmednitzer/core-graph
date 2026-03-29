"""api.mcp.tools.stix_lookup — STIX 2.1 object lookup."""

from __future__ import annotations

import json
import logging
from typing import Any

import psycopg
from psycopg.rows import dict_row
from pydantic import BaseModel

logger = logging.getLogger(__name__)

PG_DSN = "postgresql://cg_admin:cg_dev_only@localhost:5432/core_graph"

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


async def stix_lookup(stix_type: str, stix_id: str) -> dict[str, Any] | None:
    """Query a STIX 2.1 object stored as a graph vertex.

    Args:
        stix_type: STIX type (e.g., 'threat-actor', 'malware').
        stix_id: STIX identifier (e.g., 'threat-actor--uuid').

    Returns:
        STIX JSON representation if found, None otherwise.
    """
    label = STIX_LABEL_MAP.get(stix_type.lower())
    if label is None:
        raise ValueError(f"Unknown STIX type: {stix_type}")

    async with await psycopg.AsyncConnection.connect(PG_DSN, row_factory=dict_row) as conn:
        await conn.execute("select set_config('app.max_tlp', '2', true)")
        await conn.execute("set search_path = ag_catalog, '$user', public")

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

        # TODO: log to audit trail
        logger.info("STIX object found: %s/%s", stix_type, stix_id)
        return dict(row)
