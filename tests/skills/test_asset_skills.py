"""Tests for asset domain skills with mocked cypher_query."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


def _template_router(**template_results: list) -> AsyncMock:
    """Create a mock that returns results based on the template name argument.

    This avoids relying on call ordering, which is fragile with asyncio.gather.
    """
    async def _side_effect(template: str, params: dict, caller_identity=None) -> list:
        return template_results.get(template, [])

    mock = AsyncMock(side_effect=_side_effect)
    return mock


@pytest.fixture
def mock_cypher():
    """Patch cypher_query at source — works for skills that import directly."""
    with patch("api.mcp.tools.cypher_query.cypher_query", new_callable=AsyncMock) as mock:
        # Also patch the bound name in each skill module
        with (
            patch("api.mcp.skills.asset.alerts.cypher_query", mock),
            patch("api.mcp.skills.asset.compliance.cypher_query", mock),
            patch("api.mcp.skills.asset.events.cypher_query", mock),
            patch("api.mcp.skills.asset.topology.cypher_query", mock),
            patch("api.mcp.skills.asset.vulnerabilities.cypher_query", mock),
        ):
            yield mock


@pytest.mark.asyncio
async def test_full_summary_all_data() -> None:
    """Full summary with data in all sub-queries has high confidence."""
    mock = _template_router(
        asset_active_alerts=[{"alertname": "HighCPU", "severity": "critical"}],
        asset_security_events=[{"event_id": "e1", "severity": "high"}],
        asset_vulnerabilities=[{"cve_id": "CVE-2024-1234", "severity": "high"}],
        asset_compliance_status=[{"control_id": "CC-01", "evidence_status": "current"}],
        asset_topology=[{"h": {}, "interfaces": []}],
    )

    with patch("api.mcp.skills.asset.full_summary.cypher_query", mock):
        from api.mcp.skills.asset.full_summary import AssetFullSummarySkill

        skill = AssetFullSummarySkill()
        result = await skill.execute({"canonical_key": "abc123"})

    assert result.skill_name == "asset_full_summary"
    assert result.confidence == 1.0
    assert len(result.gaps) == 0
    assert "1 active alert(s)" in result.summary
    # Verify flattened data with section tags
    sections = {r["_section"] for r in result.data}
    assert sections == {"alerts", "events", "vulnerabilities", "compliance", "topology"}


@pytest.mark.asyncio
async def test_full_summary_empty_subqueries() -> None:
    """Empty sub-queries reduce confidence and add gaps."""
    mock = _template_router()  # all templates return []

    with patch("api.mcp.skills.asset.full_summary.cypher_query", mock):
        from api.mcp.skills.asset.full_summary import AssetFullSummarySkill

        skill = AssetFullSummarySkill()
        result = await skill.execute({"canonical_key": "abc123"})

    assert result.confidence == 0.5
    assert len(result.gaps) == 5


@pytest.mark.asyncio
async def test_full_summary_stale_evidence() -> None:
    """Stale compliance evidence reduces confidence."""
    mock = _template_router(
        asset_active_alerts=[{"alertname": "test"}],
        asset_security_events=[{"event_id": "e1"}],
        asset_vulnerabilities=[{"cve_id": "CVE-2024-1"}],
        asset_compliance_status=[{"control_id": "CC-01", "evidence_status": "stale"}],
        asset_topology=[{"h": {}}],
    )

    with patch("api.mcp.skills.asset.full_summary.cypher_query", mock):
        from api.mcp.skills.asset.full_summary import AssetFullSummarySkill

        skill = AssetFullSummarySkill()
        result = await skill.execute({"canonical_key": "abc123"})

    assert result.confidence == 0.9
    assert any("Stale evidence" in g for g in result.gaps)


@pytest.mark.asyncio
async def test_full_summary_missing_param() -> None:
    """Missing canonical_key raises ValueError."""
    from api.mcp.skills.asset.full_summary import AssetFullSummarySkill

    skill = AssetFullSummarySkill()
    with pytest.raises(ValueError, match="canonical_key"):
        await skill.execute({})


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
