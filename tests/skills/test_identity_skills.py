"""Tests for identity domain skills with mocked cypher_query."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


@pytest.fixture
def mock_cypher():
    with patch("api.mcp.tools.cypher_query.cypher_query", new_callable=AsyncMock) as mock:
        yield mock


@pytest.mark.asyncio
async def test_access_map_with_roles(mock_cypher: AsyncMock) -> None:
    """Access map with roles and permissions has high confidence."""
    mock_cypher.return_value = [{
        "username": "jdoe",
        "last_active": "2024-01-01T00:00:00Z",
        "direct_roles": ["admin"],
        "direct_permissions": ["read", "write"],
        "groups": ["staff"],
        "inherited_roles": ["viewer"],
        "inherited_permissions": ["read"],
    }]

    from api.mcp.skills.identity.access_map import IdentityAccessMapSkill

    skill = IdentityAccessMapSkill()
    result = await skill.execute({"principal_id": "user-123"})

    assert result.confidence == 1.0
    assert len(result.gaps) == 0


@pytest.mark.asyncio
async def test_access_map_no_principal(mock_cypher: AsyncMock) -> None:
    """Missing principal reduces confidence."""
    mock_cypher.return_value = []

    from api.mcp.skills.identity.access_map import IdentityAccessMapSkill

    skill = IdentityAccessMapSkill()
    result = await skill.execute({"principal_id": "unknown"})

    assert result.confidence == 0.8
    assert "not found" in result.gaps[0]


@pytest.mark.asyncio
async def test_audit_trail_with_events(mock_cypher: AsyncMock) -> None:
    """Audit trail with events has high confidence."""
    mock_cypher.return_value = [
        {"event_id": "e1", "event_type": "auth", "severity": "info"},
    ]

    from api.mcp.skills.identity.audit_trail import IdentityAuditTrailSkill

    skill = IdentityAuditTrailSkill()
    result = await skill.execute({"principal_id": "user-123"})

    assert result.confidence == 1.0
    assert "1 event(s)" in result.summary
