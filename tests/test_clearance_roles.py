"""Caller roles to database clearance role (ADR-0015).

Pure mapping, no database. The selection rule is the interesting part: a caller
can present several roles, and which one `api.db` assumes decides what the
request can see.
"""

from __future__ import annotations

import pytest

from api.utils.clearance_roles import CLEARANCE_ROLES, DATABASE_ROLES, database_role_for


def test_every_application_role_maps_to_its_prefixed_database_role():
    for app_role, db_role in CLEARANCE_ROLES:
        assert db_role == f"cg_{app_role}"
        assert database_role_for({"roles": [app_role]}) == db_role


def test_the_seven_role_hierarchy_is_complete():
    """The set is fixed by migrations 004 and 010. A role added to one and not
    the other is a caller that silently falls through to cg_app."""
    assert {app for app, _ in CLEARANCE_ROLES} == {
        "ciso",
        "soc_analyst",
        "compliance_officer",
        "it_operations",
        "dpo",
        "external_auditor",
        "ai_agent",
    }


@pytest.mark.parametrize(
    ("roles", "expected"),
    [
        (["soc_analyst", "ciso"], "cg_ciso"),
        (["ciso", "soc_analyst"], "cg_ciso"),
        (["dpo", "external_auditor"], "cg_external_auditor"),
        (["dpo", "it_operations", "external_auditor"], "cg_it_operations"),
    ],
)
def test_the_most_privileged_role_wins_regardless_of_order(roles, expected):
    """Matches how query_timeout_ms already resolves a multi-role caller, and is
    order-independent so the same caller gets the same role on every request."""
    assert database_role_for({"roles": roles}) == expected


@pytest.mark.parametrize(
    "identity",
    [
        None,
        {},
        {"roles": []},
        {"roles": ["admin"]},
        {"roles": ["Ciso"]},
        {"roles": ["cg_ciso"]},
        {"max_tlp": 4},
    ],
)
def test_unmapped_callers_fall_through(identity):
    """None means "stay as cg_app", which is still non-superuser and still
    policy-bound. Three of these are worth calling out:

    `admin` is what the synthetic dev identity emits and is deliberately not a
    clearance. `Ciso` differs only in case, and the IdP emits these
    case-sensitively (see policies/derived_roles.yaml), so matching loosely here
    would diverge from what Cerbos decides. `cg_ciso` is the *database* role
    name arriving where an application role belongs, which would mean someone
    confused the two namespaces; it must not resolve.
    """
    assert database_role_for(identity) is None


def test_a_bare_string_role_is_tolerated():
    """Iterating a string would test each character against the table, match
    nothing, and fall through silently."""
    assert database_role_for({"roles": "ciso"}) == "cg_ciso"


def test_non_string_entries_are_ignored_rather_than_crashing():
    assert database_role_for({"roles": [None, 3, {"ciso": True}, "ciso"]}) == "cg_ciso"


def test_everything_the_mapping_can_return_is_on_the_allowlist():
    """`api.db` interpolates this value into `SET LOCAL ROLE` because a role
    name cannot be bound as a parameter. DATABASE_ROLES is what makes that safe,
    so the two must not drift."""
    for _, db_role in CLEARANCE_ROLES:
        assert db_role in DATABASE_ROLES
    assert len(DATABASE_ROLES) == len(CLEARANCE_ROLES)
