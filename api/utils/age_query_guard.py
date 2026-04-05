"""Query guards for Apache AGE Cypher execution."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Maximum traversal depth per role (from authorization model)
ROLE_MAX_DEPTH: dict[str, int] = {
    "cg_ciso": 10,
    "cg_soc_analyst": 5,
    "cg_compliance_officer": 3,
    "cg_it_operations": 3,
    "cg_dpo": 2,
    "cg_external_auditor": 3,
    "cg_ai_agent": 4,
}

DEFAULT_MAX_DEPTH = 3
DEFAULT_TIMEOUT_MS = 30_000


def max_depth_for_role(role: str) -> int:
    """Return maximum graph traversal depth for a role."""
    return ROLE_MAX_DEPTH.get(role, DEFAULT_MAX_DEPTH)


def query_timeout_ms(caller_identity: dict | None) -> int:
    """Return query timeout in milliseconds based on caller context."""
    if caller_identity and "cg_ciso" in caller_identity.get("roles", []):
        return 120_000
    return DEFAULT_TIMEOUT_MS
