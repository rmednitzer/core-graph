"""api.mcp.tools.cypher_query — Validated Cypher query execution.

Security: Only named query templates are allowed. The tool accepts a
template name and parameters, never raw Cypher. All execution goes through
ag_catalog.cypher() with parameterised binding.

A small extension supports `template_kind: interpolated_depth` in the
companion .json schema. AGE openCypher does not parameterise the path
length quantifier `*M..N`; templates that need it carry a marker token
(e.g. `__DEPTH__`) which the loader replaces with a *validated* integer
from the matching `depth` (or `max_hops`) parameter. The integer is
re-validated by `api.utils.age_template.validate_max_hops` before
substitution; the original parameter is then stripped from the JSON
payload so it cannot collide with a real Cypher parameter binding.

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
from api.utils.age_template import validate_max_hops

logger = logging.getLogger(__name__)

try:
    from prometheus_client import Histogram

    cypher_query_duration: Histogram | None = Histogram(
        "cg_cypher_query_duration_seconds",
        "Cypher query execution time",
        ["template"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    )
except ImportError:
    cypher_query_duration = None

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


def _materialise_depth(
    template_name: str,
    cypher_str: str,
    params: dict[str, Any],
    schemas: dict[str, dict[str, Any]],
    ceiling: int = 6,
) -> tuple[str, dict[str, Any]]:
    """Replace a depth marker in the Cypher with a validated integer.

    Returns the substituted Cypher string and a new params dict that has
    the depth/max_hops parameter removed (so it does not collide with
    a Cypher `$depth` reference and inflate the agtype payload).
    """
    schema = schemas.get(template_name) or {}
    if schema.get("template_kind") != "interpolated_depth":
        return cypher_str, params
    marker = schema.get("depth_marker")
    if not marker:
        raise ValueError(
            f"template {template_name!r} marked as interpolated_depth without depth_marker"
        )
    candidate_keys = ("depth", "max_hops")
    depth_value: int | None = None
    new_params = dict(params)
    for key in candidate_keys:
        if key in new_params:
            depth_value = validate_max_hops(int(new_params[key]), ceiling=ceiling)
            new_params.pop(key)
            break
    # Fall back to the schema's declared default for the matching parameter.
    if depth_value is None:
        param_defs = schema.get("parameters", {})
        for key in candidate_keys:
            default = param_defs.get(key, {}).get("default")
            if default is not None:
                depth_value = validate_max_hops(int(default), ceiling=ceiling)
                break
    if depth_value is None:
        raise ValueError(f"template {template_name!r} requires a `depth` or `max_hops` parameter")
    if marker not in cypher_str:
        raise ValueError(f"template {template_name!r}: depth_marker {marker!r} not found in Cypher")
    return cypher_str.replace(marker, str(depth_value)), new_params


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

    # Interpolate validated depth (rejects out-of-range or non-integer input).
    cypher_str, params = _materialise_depth(template, cypher_str, params, PARAMETER_SCHEMAS)

    correlation_id = uuid.uuid4()
    caller = caller_identity or {"max_tlp": DEFAULT_TLP, "allowed_compartments": []}

    t_start = time.perf_counter()

    async with get_connection(caller) as conn:
        # statement_timeout is set uniformly by api.db.get_connection() based
        # on caller roles; do not re-set it here.

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

        elapsed = time.perf_counter() - t_start
        if cypher_query_duration is not None:
            cypher_query_duration.labels(template=template).observe(elapsed)

        elapsed_ms = elapsed * 1000
        logger.info(
            "Cypher query executed: template=%s params=%d correlation=%s rows=%d elapsed_ms=%.1f",
            template,
            len(params),
            correlation_id,
            len(rows),
            elapsed_ms,
        )
        return [dict(r) for r in rows]
