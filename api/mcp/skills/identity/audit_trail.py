"""Identity audit trail skill — security events involving a principal."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from api.mcp.skills.base import SkillBase, SkillResult
from api.mcp.tools.cypher_query import cypher_query


class IdentityAuditTrailSkill(SkillBase):
    name = "identity_audit_trail"
    description = "Security events involving a principal within a time window"
    version = "1.1.0"

    async def execute(
        self,
        params: dict[str, Any],
        caller_identity: dict[str, Any] | None = None,
    ) -> SkillResult:
        principal_id = self._require_param(params, "principal_id")
        hours_back = int(params.get("hours_back", 72))
        threshold = datetime.now(UTC) - timedelta(hours=hours_back)

        query_params = {
            "principal_id": principal_id,
            "time_threshold": threshold.isoformat(),
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
            summary=f"{len(rows)} event(s) in last {hours_back}h",
            gaps=gaps,
            sources=["layer_8_iam", "layer_2_security"],
        )
