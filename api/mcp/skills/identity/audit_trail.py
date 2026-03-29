"""Identity audit trail skill — security events involving a principal."""

from __future__ import annotations

from typing import Any

from api.mcp.skills.base import SkillBase, SkillResult
from api.mcp.tools.cypher_query import cypher_query


class IdentityAuditTrailSkill(SkillBase):
    name = "identity_audit_trail"
    description = "Security events involving a principal within a time window"
    version = "1.0.0"

    async def execute(
        self,
        params: dict[str, Any],
        caller_identity: dict[str, Any] | None = None,
    ) -> SkillResult:
        query_params = {
            "principal_id": params["principal_id"],
            "hours_back": params.get("hours_back", 72),
        }
        rows = await cypher_query("identity_audit_trail", query_params, caller_identity)

        confidence = 1.0
        gaps: list[str] = []
        if not rows:
            confidence -= 0.1
            gaps.append("No security events for this principal in the time window")

        return SkillResult(
            skill_name=self.name,
            confidence=round(confidence, 1),
            data=rows,
            summary=f"{len(rows)} event(s) in last {query_params['hours_back']}h",
            gaps=gaps,
            sources=["layer_8_iam", "layer_2_security"],
        )
