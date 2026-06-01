"""Tests for AGE query guard utilities (api.utils.age_query_guard).

These guard the role→depth/timeout lookups against the bare application-role
vocabulary the OIDC IdP emits (`ciso`, `soc_analyst`, ...). Regression target
(A-03): the tables were previously keyed on `cg_`-prefixed names, so under the
bare JWT `roles` claim that `api/db.py` feeds in, every caller silently fell
back to the default depth/timeout. The earlier version of this test asserted the
`cg_`-prefixed keys in isolation, which is why the mismatch stayed invisible.

The `cg_`-prefixed names belong to the PostgreSQL *database-role* namespace (the
RLS GRANTs in schema/migrations), which is distinct from these application roles.
"""

from __future__ import annotations

from api.utils.age_query_guard import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_TIMEOUT_MS,
    ROLE_MAX_DEPTH,
    ROLE_TIMEOUT_MS,
    max_depth_for_role,
    query_timeout_ms,
)

SEVEN_ROLE_HIERARCHY = {
    "ciso",
    "soc_analyst",
    "compliance_officer",
    "it_operations",
    "dpo",
    "external_auditor",
    "ai_agent",
}


class TestRoleVocabulary:
    """The lookup keys must be the bare JWT application roles, not cg_-prefixed."""

    def test_keys_are_bare_application_roles(self) -> None:
        for key in (*ROLE_MAX_DEPTH, *ROLE_TIMEOUT_MS):
            assert not key.startswith("cg_"), f"{key!r} must be a bare application role"

    def test_seven_role_hierarchy_present(self) -> None:
        assert set(ROLE_MAX_DEPTH) == SEVEN_ROLE_HIERARCHY


class TestMaxDepthForRole:
    """Tests for max_depth_for_role."""

    def test_ciso(self) -> None:
        assert max_depth_for_role("ciso") == 10
        assert max_depth_for_role("ciso") != DEFAULT_MAX_DEPTH

    def test_soc_analyst(self) -> None:
        assert max_depth_for_role("soc_analyst") == 5

    def test_compliance_officer(self) -> None:
        assert max_depth_for_role("compliance_officer") == 3

    def test_it_operations(self) -> None:
        assert max_depth_for_role("it_operations") == 3

    def test_dpo(self) -> None:
        assert max_depth_for_role("dpo") == 2

    def test_external_auditor(self) -> None:
        assert max_depth_for_role("external_auditor") == 3

    def test_ai_agent(self) -> None:
        assert max_depth_for_role("ai_agent") == 4

    def test_all_roles_covered(self) -> None:
        for role, depth in ROLE_MAX_DEPTH.items():
            assert max_depth_for_role(role) == depth

    def test_unknown_role_returns_default(self) -> None:
        assert max_depth_for_role("unknown_role") == DEFAULT_MAX_DEPTH

    def test_empty_string_returns_default(self) -> None:
        assert max_depth_for_role("") == DEFAULT_MAX_DEPTH

    def test_cg_prefixed_role_is_not_recognised(self) -> None:
        # A database-role string must NOT resolve here (the fixed regression).
        assert max_depth_for_role("cg_ciso") == DEFAULT_MAX_DEPTH


class TestQueryTimeoutMs:
    """Tests for query_timeout_ms."""

    def test_ciso_gets_elevated_timeout(self) -> None:
        assert query_timeout_ms({"roles": ["ciso"]}) == 120_000
        assert query_timeout_ms({"roles": ["ciso"]}) != DEFAULT_TIMEOUT_MS

    def test_ciso_among_multiple_roles(self) -> None:
        assert query_timeout_ms({"roles": ["soc_analyst", "ciso"]}) == 120_000

    def test_ai_agent_gets_elevated_timeout(self) -> None:
        assert query_timeout_ms({"roles": ["ai_agent"]}) == 60_000

    def test_highest_role_timeout_wins(self) -> None:
        assert query_timeout_ms({"roles": ["ai_agent", "ciso"]}) == 120_000

    def test_role_without_explicit_timeout_uses_default(self) -> None:
        # soc_analyst has a depth limit but no explicit timeout override.
        assert query_timeout_ms({"roles": ["soc_analyst"]}) == DEFAULT_TIMEOUT_MS

    def test_no_roles_gets_default(self) -> None:
        assert query_timeout_ms({"roles": []}) == DEFAULT_TIMEOUT_MS

    def test_none_identity_gets_default(self) -> None:
        assert query_timeout_ms(None) == DEFAULT_TIMEOUT_MS

    def test_missing_roles_key_gets_default(self) -> None:
        assert query_timeout_ms({"actor": "someone"}) == DEFAULT_TIMEOUT_MS

    def test_cg_prefixed_role_uses_default(self) -> None:
        # Regression: the old cg_-keyed tables denied every caller their limit.
        assert query_timeout_ms({"roles": ["cg_ciso"]}) == DEFAULT_TIMEOUT_MS
