"""Tests for the skill registry."""

from __future__ import annotations

from typing import Any

import pytest

from api.mcp.skills.base import SkillBase, SkillResult
from api.mcp.skills.registry import SkillRegistry


class MockSkill(SkillBase):
    name = "mock_skill"
    description = "A mock skill for testing"
    version = "0.1.0"

    async def execute(
        self,
        params: dict[str, Any],
        caller_identity: dict[str, Any] | None = None,
    ) -> SkillResult:
        return SkillResult(
            skill_name=self.name,
            confidence=1.0,
            data=[{"mock": True}],
            summary="Mock result",
        )


def test_register_and_get() -> None:
    """Register a skill and retrieve it by name."""
    reg = SkillRegistry()
    skill = MockSkill()
    reg.register(skill)
    assert reg.get_skill("mock_skill") is skill


def test_get_unknown_skill() -> None:
    """Getting an unknown skill raises KeyError."""
    reg = SkillRegistry()
    with pytest.raises(KeyError, match="Unknown skill"):
        reg.get_skill("nonexistent")


def test_list_skills() -> None:
    """list_skills returns metadata for all registered skills."""
    reg = SkillRegistry()
    reg.register(MockSkill())
    skills = reg.list_skills()
    assert len(skills) == 1
    assert skills[0]["name"] == "mock_skill"
    assert skills[0]["version"] == "0.1.0"


def test_discover_skills() -> None:
    """discover_skills finds and registers skill classes from subpackages."""
    reg = SkillRegistry()
    reg.discover_skills()
    skills = reg.list_skills()
    names = [s["name"] for s in skills]

    # Should find all 10 skills
    assert "asset_full_summary" in names
    assert "asset_compliance_status" in names
    assert "asset_vulnerabilities" in names
    assert "asset_active_alerts" in names
    assert "asset_security_events" in names
    assert "asset_topology" in names
    assert "identity_access_map" in names
    assert "identity_audit_trail" in names
    assert "threat_actor_to_asset" in names
    assert "alert_to_compliance_gap" in names
