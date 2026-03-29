"""Asset active alerts skill."""

from __future__ import annotations

from typing import Any

from api.mcp.skills.base import SkillBase, SkillResult
from api.mcp.tools.cypher_query import cypher_query


class AssetActiveAlertsSkill(SkillBase):
    name = "asset_active_alerts"
    description = "Active firing alerts for an asset, ordered by severity"
    version = "1.0.0"

    async def execute(
        self,
        params: dict[str, Any],
        caller_identity: dict[str, Any] | None = None,
    ) -> SkillResult:
        query_params = {
            "canonical_key": params["canonical_key"],
            "limit": params.get("limit", 20),
        }
        rows = await cypher_query("asset_active_alerts", query_params, caller_identity)

        confidence = 1.0
        gaps: list[str] = []
        if not rows:
            confidence -= 0.1
            gaps.append("No active alerts (host may be healthy or unmonitored)")

        return SkillResult(
            skill_name=self.name,
            confidence=round(confidence, 1),
            data=rows,
            summary=f"{len(rows)} active alert(s)",
            gaps=gaps,
            sources=["layer_7_infrastructure"],
        )
