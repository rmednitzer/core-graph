"""Tests for api.utils.caller.caller_from_request."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from api.config import DEFAULT_TLP
from api.utils.caller import caller_from_request


def _request(headers: dict[str, str] | None = None, identity: object | None = None):
    """Build a minimal FastAPI Request stand-in with state and headers."""
    return SimpleNamespace(
        headers=headers or {},
        state=SimpleNamespace(identity=identity),
    )


def test_uses_request_state_identity_when_present() -> None:
    identity = SimpleNamespace(
        sub="alice",
        max_tlp=3,
        roles=["cg_ciso"],
        allowed_compartments=["incident-7"],
    )
    caller = caller_from_request(_request(identity=identity))
    assert caller == {
        "max_tlp": 3,
        "actor": "alice",
        "roles": ["cg_ciso"],
        "allowed_compartments": ["incident-7"],
    }


def test_authenticated_roles_propagate_for_query_timeout() -> None:
    """Regression: roles were dropped, silently disabling the per-role
    statement_timeout / depth ceiling (a DoS guard)."""
    from api.utils.age_query_guard import ROLE_TIMEOUT_MS, query_timeout_ms

    identity = SimpleNamespace(
        sub="bob",
        max_tlp=4,
        roles=["cg_ciso"],
        allowed_compartments=[],
    )
    caller = caller_from_request(_request(identity=identity))
    assert query_timeout_ms(caller) == ROLE_TIMEOUT_MS["cg_ciso"]


def test_falls_back_to_default_when_no_identity_or_header() -> None:
    caller = caller_from_request(_request())
    assert caller == {
        "max_tlp": DEFAULT_TLP,
        "actor": "rest_api",
        "allowed_compartments": [],
    }


def test_honours_numeric_x_cg_tlp_header() -> None:
    caller = caller_from_request(_request(headers={"X-CG-TLP": "2"}))
    assert caller["max_tlp"] == 2


@pytest.mark.parametrize("bad", ["amber", "", "  ", "1.5", "-1nope"])
def test_non_numeric_x_cg_tlp_header_falls_back_to_default(bad: str) -> None:
    """Non-numeric header values must not turn a request into a 500."""
    caller = caller_from_request(_request(headers={"X-CG-TLP": bad}))
    assert caller["max_tlp"] == DEFAULT_TLP


def test_honor_tlp_header_false_ignores_header() -> None:
    """TAXII-style callers ignore X-CG-TLP regardless of value."""
    caller = caller_from_request(
        _request(headers={"X-CG-TLP": "4"}),
        fallback_actor="taxii_anonymous",
        honor_tlp_header=False,
    )
    assert caller["max_tlp"] == DEFAULT_TLP
    assert caller["actor"] == "taxii_anonymous"


def test_custom_fallback_actor() -> None:
    caller = caller_from_request(_request(), fallback_actor="my_service")
    assert caller["actor"] == "my_service"
