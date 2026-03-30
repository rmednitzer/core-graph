"""Asset compliance status skill."""

from __future__ import annotations

from typing import Any

from api.mcp.skills.base import SkillBase, SkillResult
from api.mcp.tools.cypher_query import cypher_query


class AssetComplianceStatusSkill(SkillBase):
    name = "asset_compliance_status"
    description = "Compliance controls and evidence freshness for an asset"
    version = "1.0.0"

    async def execute(
        self,
        params: dict[str, Any],
        caller_identity: dict[str, Any] | None = None,
    ) -> SkillResult:
        self._require_param(params, "canonical_key")
        rows = await cypher_query("asset_compliance_status", params, caller_identity)

        confidence = 1.0
        gaps: list[str] = []
        if not rows:
            confidence -= 0.1
            gaps.append("No compliance controls mapped to this asset")
        else:
            stale = [r for r in rows if r.get("evidence_status") == "stale"]
            missing = [r for r in rows if r.get("evidence_status") == "missing"]
            if stale:
                confidence -= 0.1 * len(stale)
                gaps.append(f"{len(stale)} control(s) with stale evidence")
            if missing:
                confidence -= 0.1 * len(missing)
                gaps.append(f"{len(missing)} control(s) with missing evidence")

        confidence = max(confidence, 0.0)

        return SkillResult(
            skill_name=self.name,
            confidence=round(confidence, 1),
            data=rows,
            summary=f"{len(rows)} compliance control(s) in scope",
            gaps=gaps,
            sources=["layer_4_compliance"],
        )
