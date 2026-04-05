"""Tests for AGE query guard utilities."""

from __future__ import annotations

from api.utils.age_query_guard import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_TIMEOUT_MS,
    ROLE_MAX_DEPTH,
    max_depth_for_role,
    query_timeout_ms,
)


class TestMaxDepthForRole:
    """Tests for max_depth_for_role."""

    def test_cg_ciso(self) -> None:
        assert max_depth_for_role("cg_ciso") == 10

    def test_cg_soc_analyst(self) -> None:
        assert max_depth_for_role("cg_soc_analyst") == 5

    def test_cg_compliance_officer(self) -> None:
        assert max_depth_for_role("cg_compliance_officer") == 3

    def test_cg_it_operations(self) -> None:
        assert max_depth_for_role("cg_it_operations") == 3

    def test_cg_dpo(self) -> None:
        assert max_depth_for_role("cg_dpo") == 2

    def test_cg_external_auditor(self) -> None:
        assert max_depth_for_role("cg_external_auditor") == 3

    def test_cg_ai_agent(self) -> None:
        assert max_depth_for_role("cg_ai_agent") == 4

    def test_all_roles_covered(self) -> None:
        for role, depth in ROLE_MAX_DEPTH.items():
            assert max_depth_for_role(role) == depth

    def test_unknown_role_returns_default(self) -> None:
        assert max_depth_for_role("unknown_role") == DEFAULT_MAX_DEPTH

    def test_empty_string_returns_default(self) -> None:
        assert max_depth_for_role("") == DEFAULT_MAX_DEPTH


class TestQueryTimeoutMs:
    """Tests for query_timeout_ms."""

    def test_ciso_gets_elevated_timeout(self) -> None:
        identity = {"roles": ["cg_ciso"]}
        assert query_timeout_ms(identity) == 120_000

    def test_ciso_among_multiple_roles(self) -> None:
        identity = {"roles": ["cg_soc_analyst", "cg_ciso"]}
        assert query_timeout_ms(identity) == 120_000

    def test_non_ciso_gets_default(self) -> None:
        identity = {"roles": ["cg_soc_analyst"]}
        assert query_timeout_ms(identity) == DEFAULT_TIMEOUT_MS

    def test_no_roles_gets_default(self) -> None:
        identity = {"roles": []}
        assert query_timeout_ms(identity) == DEFAULT_TIMEOUT_MS

    def test_none_identity_gets_default(self) -> None:
        assert query_timeout_ms(None) == DEFAULT_TIMEOUT_MS

    def test_missing_roles_key_gets_default(self) -> None:
        identity = {"actor": "someone"}
        assert query_timeout_ms(identity) == DEFAULT_TIMEOUT_MS

    def test_ai_agent_gets_elevated_timeout(self) -> None:
        identity = {"roles": ["cg_ai_agent"]}
        assert query_timeout_ms(identity) == 60_000

    def test_highest_role_timeout_wins(self) -> None:
        identity = {"roles": ["cg_ai_agent", "cg_ciso"]}
        assert query_timeout_ms(identity) == 120_000
