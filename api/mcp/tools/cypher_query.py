"""api.mcp.tools.cypher_query — Validated Cypher query execution.

Security: Only named query templates are allowed. The tool accepts a
template name and parameters, never raw Cypher. All execution goes through
ag_catalog.cypher() with parameterised binding.
Never constructs Cypher strings via concatenation (CVE-2022-45786 mitigation).
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

from api.config import DEFAULT_TLP
from api.db import get_connection

logger = logging.getLogger(__name__)

QUERIES_DIR = Path(__file__).resolve().parent.parent / "skills" / "queries"


def load_query_templates(queries_dir: Path) -> dict[str, str]:
    """Load all .cypher files from the queries directory.

    Returns a dict mapping template name (file stem) to Cypher string.
    """
    templates: dict[str, str] = {}
    if not queries_dir.is_dir():
        logger.warning("Queries directory not found: %s", queries_dir)
        return templates
    for cypher_file in sorted(queries_dir.glob("*.cypher")):
        name = cypher_file.stem
        templates[name] = cypher_file.read_text().strip()
    logger.info("Loaded %d query templates from %s", len(templates), queries_dir)
    return templates


def load_parameter_schemas(queries_dir: Path) -> dict[str, dict[str, Any]]:
    """Load companion .json parameter schema files.

    Returns a dict mapping template name to its parameter schema.
    """
    schemas: dict[str, dict[str, Any]] = {}
    if not queries_dir.is_dir():
        return schemas
    for json_file in sorted(queries_dir.glob("*.json")):
        name = json_file.stem
        schemas[name] = json.loads(json_file.read_text())
    return schemas


def validate_params(
    template_name: str,
    params: dict[str, Any],
    schemas: dict[str, dict[str, Any]],
) -> None:
    """Validate parameters against the companion schema.

    Raises ValueError if required parameters are missing.
    """
    schema = schemas.get(template_name)
    if schema is None:
        return  # No schema available; skip validation
    param_defs = schema.get("parameters", {})
    for param_name, param_def in param_defs.items():
        if param_def.get("required", False) and param_name not in params:
            raise ValueError(
                f"Missing required parameter {param_name!r} for template {template_name!r}"
            )


# Named query templates — loaded from .cypher files at import time.
QUERY_TEMPLATES: dict[str, str] = load_query_templates(QUERIES_DIR)
PARAMETER_SCHEMAS: dict[str, dict[str, Any]] = load_parameter_schemas(QUERIES_DIR)


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

    validate_params(template, params, PARAMETER_SCHEMAS)

    correlation_id = uuid.uuid4()
    caller = caller_identity or {"max_tlp": DEFAULT_TLP, "allowed_compartments": []}

    t_start = time.perf_counter()

    async with get_connection(caller) as conn:
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

        elapsed_ms = (time.perf_counter() - t_start) * 1000
        logger.info(
            "Cypher query executed: template=%s params=%d correlation=%s "
            "rows=%d elapsed_ms=%.1f",
            template,
            len(params),
            correlation_id,
            len(rows),
            elapsed_ms,
        )
        return [dict(r) for r in rows]
