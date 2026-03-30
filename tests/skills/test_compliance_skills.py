"""Tests for compliance domain skills with mocked cypher_query."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


@pytest.fixture
def mock_cypher():
    with patch("api.mcp.tools.cypher_query.cypher_query", new_callable=AsyncMock) as mock:
        with patch("api.mcp.skills.compliance.alert_gap.cypher_query", mock):
            yield mock


@pytest.mark.asyncio
async def test_alert_gap_found(mock_cypher: AsyncMock) -> None:
    """Alert with compliance gaps reports them."""
    mock_cypher.return_value = [
        {
            "alertname": "HighCPU",
            "host_name": "web-01",
            "control_id": "CC-01",
            "evidence_status": "stale",
            "last_evidence": "2024-01-01",
        },
        {
            "alertname": "HighCPU",
            "host_name": "web-01",
            "control_id": "CC-02",
            "evidence_status": "missing",
            "last_evidence": None,
        },
    ]

    from api.mcp.skills.compliance.alert_gap import AlertToComplianceGapSkill

    skill = AlertToComplianceGapSkill()
    result = await skill.execute({"alertname": "HighCPU"})

    assert result.confidence < 1.0
    assert len(result.gaps) == 2
    assert "2 compliance gap(s)" in result.summary


@pytest.mark.asyncio
async def test_alert_gap_none(mock_cypher: AsyncMock) -> None:
    """Alert with no compliance gaps has high confidence."""
    mock_cypher.return_value = []

    from api.mcp.skills.compliance.alert_gap import AlertToComplianceGapSkill

    skill = AlertToComplianceGapSkill()
    result = await skill.execute({"alertname": "HealthCheck"})

    assert result.confidence == 0.9
    assert "No compliance gaps" in result.gaps[0]
