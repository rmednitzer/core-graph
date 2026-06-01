"""Query guards for Apache AGE Cypher execution."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Maximum traversal depth per role (from the authorization model).
#
# Keys are the *application* role names as the OIDC IdP emits them in the JWT
# `roles` claim — the bare seven-role hierarchy (`ciso`, `soc_analyst`, ...) —
# because these tables are looked up against `caller_identity["roles"]`. This is
# a DIFFERENT namespace from the PostgreSQL database roles (`cg_ciso`, ...) that
# the RLS GRANTs in schema/migrations target; do not `cg_`-prefix these keys, or
# every caller silently falls back to the defaults below. See ADR-0008.
ROLE_MAX_DEPTH: dict[str, int] = {
    "ciso": 10,
    "soc_analyst": 5,
    "compliance_officer": 3,
    "it_operations": 3,
    "dpo": 2,
    "external_auditor": 3,
    "ai_agent": 4,
}

DEFAULT_MAX_DEPTH = 3
DEFAULT_TIMEOUT_MS = 30_000

# Role-specific query timeouts (milliseconds), keyed by the same bare
# application role names as ROLE_MAX_DEPTH. CISO and AI agents get higher
# timeouts for complex cross-domain queries.
ROLE_TIMEOUT_MS: dict[str, int] = {
    "ciso": 120_000,
    "ai_agent": 60_000,
}


def max_depth_for_role(role: str) -> int:
    """Return maximum graph traversal depth for a role."""
    return ROLE_MAX_DEPTH.get(role, DEFAULT_MAX_DEPTH)


def query_timeout_ms(caller_identity: dict | None) -> int:
    """Return query timeout in milliseconds based on caller context.

    Checks caller roles against ROLE_TIMEOUT_MS and returns the highest
    applicable timeout (most permissive role wins).
    """
    if not caller_identity:
        return DEFAULT_TIMEOUT_MS
    roles = caller_identity.get("roles", [])
    if not roles:
        return DEFAULT_TIMEOUT_MS
    applicable = [ROLE_TIMEOUT_MS[r] for r in roles if r in ROLE_TIMEOUT_MS]
    return max(applicable) if applicable else DEFAULT_TIMEOUT_MS
