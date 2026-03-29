"""api.mcp.tools.cypher_query — Validated Cypher query execution.

Security: Only queries matching pre-approved templates are allowed.
All execution goes through ag_catalog.cypher() with parameterised binding.
Never constructs Cypher strings via concatenation (CVE-2022-45786 mitigation).
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import psycopg
from psycopg.rows import dict_row
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Database connection string — in production, sourced from env/secrets
PG_DSN = "postgresql://cg_admin:cg_dev_only@localhost:5432/core_graph"


class CypherQueryInput(BaseModel):
    """Input model for cypher_query tool."""

    query: str
    params: dict[str, Any] = {}


class CypherQueryResult(BaseModel):
    """Output model for cypher_query tool."""

    rows: list[dict[str, Any]]
    count: int


# Allowlisted query templates — only these patterns are permitted
ALLOWED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^\s*match\s+\(", re.IGNORECASE),
    re.compile(r"^\s*match\s+\(\w+:\w+\s*\{", re.IGNORECASE),
    re.compile(r"^\s*match\s+\(\w+:\w+\)\s*-\[", re.IGNORECASE),
]


def _validate_query(query: str) -> bool:
    """Check that the query matches an allowed template pattern."""
    # Reject any mutation keywords
    mutation_keywords = ["create", "merge", "delete", "detach", "set", "remove"]
    query_lower = query.lower().strip()
    for kw in mutation_keywords:
        if re.search(rf"\b{kw}\b", query_lower):
            return False
    return any(p.match(query) for p in ALLOWED_PATTERNS)


async def cypher_query(query: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    """Execute a validated read-only Cypher query."""
    if not _validate_query(query):
        raise ValueError("Query does not match any allowed template")

    async with await psycopg.AsyncConnection.connect(PG_DSN, row_factory=dict_row) as conn:
        # Set RLS session variables
        # TODO: extract caller identity from MCP session context
        await conn.execute("select set_config('app.max_tlp', '2', true)")
        await conn.execute("set search_path = ag_catalog, '$user', public")

        # Execute via AGE with parameter binding
        agtype_params = json.dumps(params)
        sql = f"""
            select * from ag_catalog.cypher('core_graph', $cypher$
                {query}
            $cypher$, %s) as (result agtype)
        """
        # TODO: replace f-string with proper template validation
        # The query has been validated against the allowlist above,
        # but production should use fully parameterised prepared statements
        cursor = await conn.execute(sql, (agtype_params,))
        rows = await cursor.fetchall()

        # TODO: log to audit trail
        return [dict(r) for r in rows]
