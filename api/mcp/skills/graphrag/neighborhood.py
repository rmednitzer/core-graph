"""GraphRAG: N-hop neighbourhood subgraph from an anchor entity."""

from __future__ import annotations

import json
from typing import Any

from api.config import DEFAULT_TLP
from api.db import get_connection
from api.mcp.skills.base import SkillBase, SkillResult
from api.mcp.tools.cypher_query import cypher_query
from api.utils.age_template import validate_edge_label, validate_max_hops
from api.utils.cypher_safety import validate_label


class GraphRAGNeighborhoodSkill(SkillBase):
    name = "graphrag_neighborhood"
    description = (
        "N-hop neighbourhood subgraph from an anchor entity, "
        "RLS-filtered, with optional edge_type filter."
    )
    version = "1.1.0"

    async def execute(
        self,
        params: dict[str, Any],
        caller_identity: dict[str, Any] | None = None,
    ) -> SkillResult:
        entity_id = int(self._require_param(params, "entity_id"))
        depth = validate_max_hops(int(params.get("depth", 2)))
        edge_type_filter = params.get("edge_type_filter")

        if edge_type_filter is None:
            rows = await cypher_query(
                "graphrag_neighborhood",
                {"entity_id": entity_id, "depth": depth},
                caller_identity,
            )
        else:
            # AGE openCypher does not parameterise relationship types in
            # variable-length patterns. Validate against the allowlist
            # then interpolate inline. The validate_edge_label call raises
            # ValueError on any input outside the registered set so we never
            # interpolate caller-supplied text without a server-side check.
            edge_label = validate_edge_label(edge_type_filter)
            rows = await self._typed_neighborhood(
                entity_id=entity_id,
                depth=depth,
                edge_label=edge_label,
                caller_identity=caller_identity,
            )

        gaps: list[str] = []
        if not rows:
            base_msg = f"entity {entity_id} has no {depth}-hop neighbours visible to caller"
            if edge_type_filter:
                base_msg = f"{base_msg} on edge type {edge_type_filter!r}"
            gaps.append(base_msg)

        confidence = 0.4 + 0.05 * min(len(rows) // 5, 12)

        return SkillResult(
            skill_name=self.name,
            confidence=round(min(confidence, 1.0), 2),
            data=rows,
            summary=f"{len(rows)} neighbour record(s) at {depth}-hop depth",
            gaps=gaps,
            sources=["layer_7_infrastructure", "layer_8_iam"],
        )

    async def _typed_neighborhood(
        self,
        *,
        entity_id: int,
        depth: int,
        edge_label: str,
        caller_identity: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        """Run the neighbourhood query with an explicit relationship type.

        edge_label MUST already be validated by `validate_edge_label`; we
        re-assert here as a defence-in-depth check.
        """
        # Re-validate before any string interpolation reaches the DB.
        # validate_label() asserts the character set; validate_edge_label()
        # additionally asserts allowlist membership. Both are required.
        edge_label = validate_label(validate_edge_label(edge_label))
        # `depth` is an int (already validated), `edge_label` is allowlisted.
        cypher = (
            f"match (v) where id(v) = $entity_id "
            f"optional match (v)-[edges:{edge_label}*1..{int(depth)}]-(neighbour) "
            f"return id(v) as anchor_id, "
            f"id(neighbour) as neighbour_id, "
            f"labels(neighbour) as neighbour_labels, "
            f"neighbour.canonical_key as canonical_key, "
            f"neighbour.tlp_level as tlp_level, "
            f"length(edges) as hops"
        )

        caller = caller_identity or {"max_tlp": DEFAULT_TLP, "allowed_compartments": []}
        async with get_connection(caller) as conn:
            # cypher is built only from validate_label() output and an int.
            sql = (
                "select * from ag_catalog.cypher('core_graph', $cypher$\n"
                f"                {cypher}\n"
                "            $cypher$, %s) as (result agtype)"
            )
            cursor = await conn.execute(sql, (json.dumps({"entity_id": entity_id}),))
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]
