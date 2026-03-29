"""Alert to compliance gap skill — compliance gaps created by alert conditions."""

from __future__ import annotations

from typing import Any

from api.mcp.skills.base import SkillBase, SkillResult
from api.mcp.tools.cypher_query import cypher_query


class AlertToComplianceGapSkill(SkillBase):
    name = "alert_to_compliance_gap"
    description = "Compliance gaps created by an alert condition: stale or missing evidence"
    version = "1.0.0"

    async def execute(
        self,
        params: dict[str, Any],
        caller_identity: dict[str, Any] | None = None,
    ) -> SkillResult:
        rows = await cypher_query("alert_to_compliance_gap", params, caller_identity)

        confidence = 1.0
        gaps: list[str] = []
        if not rows:
            confidence -= 0.1
            gaps.append("No compliance gaps found for this alert")
        else:
            missing = [r for r in rows if r.get("evidence_status") == "missing"]
            stale = [r for r in rows if r.get("evidence_status") == "stale"]
            if missing:
                gaps.append(f"{len(missing)} control(s) with missing evidence")
                confidence -= 0.1
            if stale:
                gaps.append(f"{len(stale)} control(s) with stale evidence")
                confidence -= 0.1

        confidence = max(confidence, 0.0)

        return SkillResult(
            skill_name=self.name,
            confidence=round(confidence, 1),
            data=rows,
            summary=f"{len(rows)} compliance gap(s) linked to alert",
            gaps=gaps,
            sources=["layer_4_compliance", "layer_7_infrastructure"],
        )
