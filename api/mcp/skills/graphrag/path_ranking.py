"""GraphRAG: ranked paths between two entities."""

from __future__ import annotations

from typing import Any

from api.mcp.skills.base import SkillBase, SkillResult
from api.mcp.tools.cypher_query import cypher_query


class GraphRAGPathRankingSkill(SkillBase):
    name = "graphrag_path_ranking"
    description = (
        "All paths between source_entity and target_entity up to max_hops. "
        "Ranked by product(edge.confidence) * exp(-0.25 * length)."
    )
    version = "1.0.0"

    async def execute(
        self,
        params: dict[str, Any],
        caller_identity: dict[str, Any] | None = None,
    ) -> SkillResult:
        source_id = int(self._require_param(params, "source_id"))
        target_id = int(self._require_param(params, "target_id"))
        max_hops = int(params.get("max_hops", 4))

        rows = await cypher_query(
            "graphrag_path_ranking",
            {
                "source_id": source_id,
                "target_id": target_id,
                "max_hops": max_hops,
            },
            caller_identity,
        )

        gaps: list[str] = []
        if not rows:
            gaps.append(
                f"no paths of length 1..{max_hops} between {source_id} and {target_id}"
            )

        confidence = 0.4 + 0.05 * min(len(rows), 12)

        return SkillResult(
            skill_name=self.name,
            confidence=round(min(confidence, 1.0), 2),
            data=rows,
            summary=f"{len(rows)} ranked path(s) of length 1..{max_hops}",
            gaps=gaps,
            sources=["layer_1_threat_intel", "layer_7_infrastructure", "layer_8_iam"],
        )
