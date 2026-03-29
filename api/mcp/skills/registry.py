"""api.mcp.skills.registry — Skill discovery and registration.

Discovers SkillBase subclasses from skill subpackages and provides
lookup by name for the MCP server.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import Any

from api.mcp.skills.base import SkillBase

logger = logging.getLogger(__name__)

# Subpackages containing skill implementations.
_SKILL_PACKAGES = [
    "api.mcp.skills.asset",
    "api.mcp.skills.identity",
    "api.mcp.skills.threat",
    "api.mcp.skills.compliance",
]


class SkillRegistry:
    """Registry for skill lookup and introspection."""

    def __init__(self) -> None:
        self._skills: dict[str, SkillBase] = {}

    def register(self, skill: SkillBase) -> None:
        """Register a skill instance by name."""
        if skill.name in self._skills:
            logger.warning("Overwriting skill registration: %s", skill.name)
        self._skills[skill.name] = skill
        logger.info("Registered skill: %s v%s", skill.name, skill.version)

    def get_skill(self, name: str) -> SkillBase:
        """Resolve a skill by name.

        Raises KeyError if the skill is not registered.
        """
        try:
            return self._skills[name]
        except KeyError:
            raise KeyError(
                f"Unknown skill: {name!r}. Available: {sorted(self._skills)}"
            ) from None

    def list_skills(self) -> list[dict[str, Any]]:
        """Return metadata for all registered skills."""
        return [
            {
                "name": s.name,
                "description": s.description,
                "version": s.version,
            }
            for s in self._skills.values()
        ]

    def discover_skills(self) -> None:
        """Import all skill subpackages and register SkillBase subclasses."""
        for package_name in _SKILL_PACKAGES:
            try:
                package = importlib.import_module(package_name)
            except ModuleNotFoundError:
                logger.debug("Skill package not found (yet): %s", package_name)
                continue

            # Walk all modules in the package
            package_path = getattr(package, "__path__", None)
            if package_path is None:
                continue

            for _importer, module_name, _ispkg in pkgutil.iter_modules(package_path):
                full_name = f"{package_name}.{module_name}"
                try:
                    mod = importlib.import_module(full_name)
                except Exception:
                    logger.warning("Failed to import skill module: %s", full_name, exc_info=True)
                    continue

                # Find and instantiate all SkillBase subclasses in the module
                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, SkillBase)
                        and attr is not SkillBase
                        and hasattr(attr, "name")
                    ):
                        try:
                            instance = attr()
                            self.register(instance)
                        except Exception:
                            logger.warning(
                                "Failed to instantiate skill: %s.%s",
                                full_name,
                                attr_name,
                                exc_info=True,
                            )


# Module-level singleton; populated at MCP server startup.
registry = SkillRegistry()
