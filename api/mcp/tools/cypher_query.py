"""api.mcp.tools.cypher_query — Validated Cypher query execution.

Security: Only named query templates are allowed. The tool accepts a
template name and parameters, never raw Cypher. All execution goes through
ag_catalog.cypher() with parameterised binding.
Never constructs Cypher strings via concatenation (CVE-2022-45786 mitigation).
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

import psycopg
from psycopg.rows import dict_row
from pydantic import BaseModel

from api.config import DEFAULT_TLP, PG_DSN

logger = logging.getLogger(__name__)


class CypherQueryInput(BaseModel):
    """Input model for cypher_query tool."""

    template: str
    params: dict[str, Any] = {}


class CypherQueryResult(BaseModel):
    """Output model for cypher_query tool."""

    rows: list[dict[str, Any]]
    count: int


# Named query templates — only these are permitted.
# Keys are template names; values are parameterised Cypher strings.
QUERY_TEMPLATES: dict[str, str] = {
    "get_entity_by_value": ("match (v {value: $value}) return v"),
    "get_entity_by_label_and_value": ("match (v {value: $value}) where label(v) = $label return v"),
    "get_neighbours": ("match (v {value: $value})-[e]-(n) return v, e, n"),
    "get_threat_actor_campaigns": (
        "match (ta:ThreatActor {name: $name})-[r:attributed_to]-(c:Campaign) return ta, r, c"
    ),
    "get_indicator_relationships": ("match (i:Indicator {value: $value})-[r]-(n) return i, r, n"),
    "get_stix_by_id": ("match (v {stix_id: $stix_id}) return v"),
    "get_attack_pattern_usage": (
        "match (a:AttackPattern {name: $name})-[r:uses]-(n) return a, r, n"
    ),
    "count_entities_by_label": ("match (v) where label(v) = $label return count(v) as cnt"),
}


async def cypher_query(
    template: str,
    params: dict[str, Any],
    caller_identity: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Execute a validated read-only Cypher query via named template.

    Args:
        template: Name of a pre-approved query template.
        params: Parameters to bind into the template.
        caller_identity: MCP session context for RLS enforcement.

    Returns:
        List of result rows as dicts.
    """
    cypher_str = QUERY_TEMPLATES.get(template)
    if cypher_str is None:
        raise ValueError(
            f"Unknown query template: {template!r}. Available: {sorted(QUERY_TEMPLATES)}"
        )

    # Determine TLP level from caller identity or default
    max_tlp = str(DEFAULT_TLP)
    allowed_compartments = ""
    if caller_identity:
        max_tlp = str(caller_identity.get("max_tlp", DEFAULT_TLP))
        allowed_compartments = ",".join(caller_identity.get("allowed_compartments", []))

    correlation_id = uuid.uuid4()

    async with await psycopg.AsyncConnection.connect(PG_DSN, row_factory=dict_row) as conn:
        # Set RLS session variables
        await conn.execute("select set_config('app.max_tlp', %s, true)", (max_tlp,))
        await conn.execute(
            "select set_config('app.allowed_compartments', %s, true)",
            (allowed_compartments,),
        )
        await conn.execute("set search_path = ag_catalog, '$user', public")

        # Execute via AGE with parameter binding
        agtype_params = json.dumps(params)
        sql = (
            "select * from ag_catalog.cypher('core_graph', $cypher$\n"
            f"                {cypher_str}\n"
            "            $cypher$, %s) as (result agtype)"
        )

        cursor = await conn.execute(sql, (agtype_params,))
        rows = await cursor.fetchall()

        # Write audit log entry
        await conn.execute(
            """
            insert into audit_log
                (entity_label, operation, actor, correlation_id)
            values (%s, %s, %s, %s)
            """,
            (
                f"cypher:{template}",
                "QUERY",
                caller_identity.get("actor", "mcp") if caller_identity else "mcp",
                correlation_id,
            ),
        )
        await conn.commit()

        logger.info(
            "Cypher query executed: template=%s correlation=%s rows=%d",
            template,
            correlation_id,
            len(rows),
        )
        return [dict(r) for r in rows]
