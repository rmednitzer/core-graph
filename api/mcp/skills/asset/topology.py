"""Asset topology skill."""

from __future__ import annotations

from typing import Any

from api.mcp.skills.base import SkillBase, SkillResult
from api.mcp.tools.cypher_query import cypher_query


class AssetTopologySkill(SkillBase):
    name = "asset_topology"
    description = "Infrastructure topology: interfaces, networks, sites, services"
    version = "1.0.0"

    async def execute(
        self,
        params: dict[str, Any],
        caller_identity: dict[str, Any] | None = None,
    ) -> SkillResult:
        self._require_param(params, "canonical_key")
        rows = await cypher_query("asset_topology", params, caller_identity)

        confidence = 1.0
        gaps: list[str] = []
        if not rows:
            confidence -= 0.2
            gaps.append("Host not found or no topology data")

        return SkillResult(
            skill_name=self.name,
            confidence=round(confidence, 1),
            data=rows,
            summary=f"Topology data for {len(rows)} host(s)",
            gaps=gaps,
            sources=["layer_7_infrastructure"],
        )
