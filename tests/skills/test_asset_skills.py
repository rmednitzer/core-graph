"""Tests for asset domain skills with mocked cypher_query."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


@pytest.fixture
def mock_cypher():
    """Patch cypher_query to return controlled data."""
    with patch("api.mcp.tools.cypher_query.cypher_query", new_callable=AsyncMock) as mock:
        yield mock


@pytest.mark.asyncio
async def test_full_summary_all_data(mock_cypher: AsyncMock) -> None:
    """Full summary with data in all sub-queries has high confidence."""
    mock_cypher.side_effect = [
        [{"alertname": "HighCPU", "severity": "critical"}],  # alerts
        [{"event_id": "e1", "severity": "high"}],  # events
        [{"cve_id": "CVE-2024-1234", "severity": "high"}],  # vulns
        [{"control_id": "CC-01", "evidence_status": "current"}],  # compliance
        [{"h": {}, "interfaces": []}],  # topology
    ]

    from api.mcp.skills.asset.full_summary import AssetFullSummarySkill

    skill = AssetFullSummarySkill()
    result = await skill.execute({"canonical_key": "abc123"})

    assert result.skill_name == "asset_full_summary"
    assert result.confidence == 1.0
    assert len(result.gaps) == 0
    assert "1 active alert(s)" in result.summary


@pytest.mark.asyncio
async def test_full_summary_empty_subqueries(mock_cypher: AsyncMock) -> None:
    """Empty sub-queries reduce confidence and add gaps."""
    mock_cypher.side_effect = [
        [],  # alerts
        [],  # events
        [],  # vulns
        [],  # compliance
        [],  # topology
    ]

    from api.mcp.skills.asset.full_summary import AssetFullSummarySkill

    skill = AssetFullSummarySkill()
    result = await skill.execute({"canonical_key": "abc123"})

    assert result.confidence == 0.5
    assert len(result.gaps) == 5


@pytest.mark.asyncio
async def test_full_summary_stale_evidence(mock_cypher: AsyncMock) -> None:
    """Stale compliance evidence reduces confidence."""
    mock_cypher.side_effect = [
        [{"alertname": "test"}],  # alerts
        [{"event_id": "e1"}],  # events
        [{"cve_id": "CVE-2024-1"}],  # vulns
        [{"control_id": "CC-01", "evidence_status": "stale"}],  # stale!
        [{"h": {}}],  # topology
    ]

    from api.mcp.skills.asset.full_summary import AssetFullSummarySkill

    skill = AssetFullSummarySkill()
    result = await skill.execute({"canonical_key": "abc123"})

    assert result.confidence == 0.9
    assert any("Stale evidence" in g for g in result.gaps)


@pytest.mark.asyncio
async def test_alerts_skill_empty(mock_cypher: AsyncMock) -> None:
    """Empty alerts returns gap about possible healthy host."""
    mock_cypher.return_value = []

    from api.mcp.skills.asset.alerts import AssetActiveAlertsSkill

    skill = AssetActiveAlertsSkill()
    result = await skill.execute({"canonical_key": "abc123"})

    assert result.confidence == 0.9
    assert "unmonitored" in result.gaps[0]


@pytest.mark.asyncio
async def test_vulnerabilities_unpatched(mock_cypher: AsyncMock) -> None:
    """Unpatched vulnerabilities are flagged in gaps."""
    mock_cypher.return_value = [
        {"cve_id": "CVE-2024-1", "patch_exists": False},
        {"cve_id": "CVE-2024-2", "patch_exists": True},
    ]

    from api.mcp.skills.asset.vulnerabilities import AssetVulnerabilitiesSkill

    skill = AssetVulnerabilitiesSkill()
    result = await skill.execute({"canonical_key": "abc123"})

    assert result.confidence == 1.0
    assert any("unpatched" in g for g in result.gaps)


@pytest.mark.asyncio
async def test_compliance_stale_and_missing(mock_cypher: AsyncMock) -> None:
    """Stale and missing evidence both reduce confidence."""
    mock_cypher.return_value = [
        {"control_id": "CC-01", "evidence_status": "stale"},
        {"control_id": "CC-02", "evidence_status": "missing"},
        {"control_id": "CC-03", "evidence_status": "current"},
    ]

    from api.mcp.skills.asset.compliance import AssetComplianceStatusSkill

    skill = AssetComplianceStatusSkill()
    result = await skill.execute({"canonical_key": "abc123"})

    assert result.confidence < 1.0
    assert len(result.gaps) == 2
