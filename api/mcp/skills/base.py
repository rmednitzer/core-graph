"""api.mcp.skills.base — Skill base class and result type.

Skills are named, versioned, composable MCP capabilities that combine
query templates with result formatting, confidence tagging, and natural
language descriptions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SkillResult:
    """Structured result returned by every skill execution."""

    skill_name: str
    confidence: float  # 0.0-1.0
    data: list[dict[str, Any]]
    summary: str  # one-sentence human-readable summary
    gaps: list[str] = field(default_factory=list)  # what data was missing or stale
    sources: list[str] = field(default_factory=list)  # which graph layers were queried


class SkillBase(ABC):
    """Abstract base class for all core-graph skills.

    Subclasses must set name, description, version as class attributes
    and implement the execute() method.
    """

    name: str
    description: str
    version: str

    def _require_param(self, params: dict[str, Any], key: str) -> Any:
        """Extract a required parameter, raising ValueError if absent."""
        if key not in params:
            raise ValueError(f"Skill {self.name!r} requires parameter {key!r}")
        return params[key]

    @abstractmethod
    async def execute(
        self,
        params: dict[str, Any],
        caller_identity: dict[str, Any] | None = None,
    ) -> SkillResult:
        """Execute the skill and return a structured result.

        Args:
            params: Skill-specific parameters.
            caller_identity: MCP session context for RLS enforcement.

        Returns:
            SkillResult with data, confidence, and metadata.
        """
        ...
