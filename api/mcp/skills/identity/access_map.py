"""Identity access map skill — effective permissions for a principal."""

from __future__ import annotations

from typing import Any

from api.mcp.skills.base import SkillBase, SkillResult
from api.mcp.tools.cypher_query import cypher_query


class IdentityAccessMapSkill(SkillBase):
    name = "identity_access_map"
    description = "Effective permissions for a principal: direct and inherited via groups"
    version = "1.0.0"

    async def execute(
        self,
        params: dict[str, Any],
        caller_identity: dict[str, Any] | None = None,
    ) -> SkillResult:
        self._require_param(params, "principal_id")
        rows = await cypher_query("identity_access_map", params, caller_identity)

        confidence = 1.0
        gaps: list[str] = []
        if not rows:
            confidence -= 0.2
            gaps.append("Principal not found in the graph")
        else:
            row = rows[0]
            if not row.get("direct_roles") and not row.get("inherited_roles"):
                confidence -= 0.2
                gaps.append("No roles assigned")
            if not row.get("direct_permissions") and not row.get("inherited_permissions"):
                confidence -= 0.1
                gaps.append("No permissions resolved")

        confidence = max(confidence, 0.0)

        return SkillResult(
            skill_name=self.name,
            confidence=round(confidence, 1),
            data=rows,
            summary=f"Access map for {len(rows)} principal(s)",
            gaps=gaps,
            sources=["layer_8_iam"],
        )
