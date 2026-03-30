"""Asset vulnerabilities skill."""

from __future__ import annotations

from typing import Any

from api.mcp.skills.base import SkillBase, SkillResult
from api.mcp.tools.cypher_query import cypher_query


class AssetVulnerabilitiesSkill(SkillBase):
    name = "asset_vulnerabilities"
    description = "Vulnerabilities affecting an asset via indicator-to-CVE traversal"
    version = "1.0.0"

    async def execute(
        self,
        params: dict[str, Any],
        caller_identity: dict[str, Any] | None = None,
    ) -> SkillResult:
        self._require_param(params, "canonical_key")
        rows = await cypher_query("asset_vulnerabilities", params, caller_identity)

        confidence = 1.0
        gaps: list[str] = []
        if not rows:
            confidence -= 0.2
            gaps.append("No vulnerabilities linked to this asset")
        else:
            unpatched = [r for r in rows if not r.get("patch_exists")]
            if unpatched:
                gaps.append(f"{len(unpatched)} unpatched vulnerability(ies)")

        confidence = max(confidence, 0.0)

        return SkillResult(
            skill_name=self.name,
            confidence=round(confidence, 1),
            data=rows,
            summary=f"{len(rows)} vulnerability(ies) found",
            gaps=gaps,
            sources=["layer_1_threat_intel", "layer_7_infrastructure"],
        )
