"""Asset full summary skill — complete asset profile across all domains."""

from __future__ import annotations

import asyncio
from typing import Any

from api.mcp.skills.base import SkillBase, SkillResult
from api.mcp.tools.cypher_query import cypher_query


class AssetFullSummarySkill(SkillBase):
    name = "asset_full_summary"
    description = "Complete asset profile: alerts, events, vulnerabilities, compliance, topology"
    version = "1.0.0"

    async def execute(
        self,
        params: dict[str, Any],
        caller_identity: dict[str, Any] | None = None,
    ) -> SkillResult:
        canonical_key = self._require_param(params, "canonical_key")
        base = {"canonical_key": canonical_key}

        # Execute sub-queries in parallel
        alerts_task = cypher_query("asset_active_alerts", {**base, "limit": 20}, caller_identity)
        events_task = cypher_query(
            "asset_security_events", {**base, "hours_back": 24}, caller_identity
        )
        vulns_task = cypher_query("asset_vulnerabilities", base, caller_identity)
        compliance_task = cypher_query("asset_compliance_status", base, caller_identity)
        topology_task = cypher_query("asset_topology", base, caller_identity)

        alerts, events, vulns, compliance, topology = await asyncio.gather(
            alerts_task, events_task, vulns_task, compliance_task, topology_task
        )

        # Confidence scoring: 1.0 base, -0.1 per empty sub-query
        confidence = 1.0
        gaps: list[str] = []
        if not alerts:
            confidence -= 0.1
            gaps.append("No active alerts found")
        if not events:
            confidence -= 0.1
            gaps.append("No recent security events")
        if not vulns:
            confidence -= 0.1
            gaps.append("No vulnerability data")
        if not compliance:
            confidence -= 0.1
            gaps.append("No compliance controls mapped")
        if not topology:
            confidence -= 0.1
            gaps.append("No topology data")

        # Check for stale evidence in compliance
        for ctrl in compliance:
            if ctrl.get("evidence_status") == "stale":
                gaps.append(f"Stale evidence for control {ctrl.get('control_id', 'unknown')}")
                confidence -= 0.1

        confidence = max(confidence, 0.0)

        data = {
            "alerts": alerts,
            "events": events,
            "vulnerabilities": vulns,
            "compliance": compliance,
            "topology": topology,
        }

        summary_parts = [
            f"{len(alerts)} active alert(s)",
            f"{len(events)} event(s) in last 24h",
            f"{len(vulns)} vulnerability(ies)",
            f"{len(compliance)} compliance control(s)",
        ]

        return SkillResult(
            skill_name=self.name,
            confidence=round(confidence, 1),
            data=[data],
            summary=f"Asset summary: {', '.join(summary_parts)}",
            gaps=gaps,
            sources=["layer_2_security", "layer_4_compliance", "layer_7_infrastructure"],
        )
