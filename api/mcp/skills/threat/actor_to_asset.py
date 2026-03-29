"""Threat actor to asset skill — assets affected by a threat actor."""

from __future__ import annotations

from typing import Any

from api.mcp.skills.base import SkillBase, SkillResult
from api.mcp.tools.cypher_query import cypher_query


class ThreatActorToAssetSkill(SkillBase):
    name = "threat_actor_to_asset"
    description = "Assets affected by a threat actor via attack patterns and vulnerabilities"
    version = "1.0.0"

    async def execute(
        self,
        params: dict[str, Any],
        caller_identity: dict[str, Any] | None = None,
    ) -> SkillResult:
        rows = await cypher_query("threat_actor_to_asset", params, caller_identity)

        confidence = 1.0
        gaps: list[str] = []
        if not rows:
            confidence -= 0.2
            gaps.append("Threat actor not found or no linked assets")
        else:
            assets_with_alerts = [r for r in rows if r.get("has_active_alert")]
            if not assets_with_alerts:
                gaps.append("No active alerts on affected assets")

        confidence = max(confidence, 0.0)

        return SkillResult(
            skill_name=self.name,
            confidence=round(confidence, 1),
            data=rows,
            summary=f"{len(rows)} asset(s) potentially affected",
            gaps=gaps,
            sources=["layer_1_threat_intel", "layer_7_infrastructure"],
        )
