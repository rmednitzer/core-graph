"""Tests for threat domain skills with mocked cypher_query."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


@pytest.fixture
def mock_cypher():
    with patch("api.mcp.tools.cypher_query.cypher_query", new_callable=AsyncMock) as mock:
        yield mock


@pytest.mark.asyncio
async def test_threat_actor_to_asset_found(mock_cypher: AsyncMock) -> None:
    """Threat actor linked to assets has high confidence."""
    mock_cypher.return_value = [
        {
            "asset_name": "web-01",
            "asset_key": "abc123",
            "cve_id": "CVE-2024-1",
            "vuln_severity": "critical",
            "has_active_alert": True,
            "attack_patterns": ["T1059"],
        },
    ]

    from api.mcp.skills.threat.actor_to_asset import ThreatActorToAssetSkill

    skill = ThreatActorToAssetSkill()
    result = await skill.execute({"threat_actor_name": "APT29"})

    assert result.confidence == 1.0
    assert "1 asset(s)" in result.summary


@pytest.mark.asyncio
async def test_threat_actor_not_found(mock_cypher: AsyncMock) -> None:
    """Unknown threat actor reduces confidence."""
    mock_cypher.return_value = []

    from api.mcp.skills.threat.actor_to_asset import ThreatActorToAssetSkill

    skill = ThreatActorToAssetSkill()
    result = await skill.execute({"threat_actor_name": "Unknown"})

    assert result.confidence == 0.8
    assert "not found" in result.gaps[0]
