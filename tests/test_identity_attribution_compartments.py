"""Verify identity_attribution.assert_identity_attribution widens compartments.

The writer creates a TLP:RED edge with `compartment: investigation_id`. RLS
policy filters edge reads by compartment membership. If the writer's session
GUC `app.allowed_compartments` does not include the investigation_id, the
edge becomes invisible to the same caller immediately after creation
(write-then-read visibility gap).

This test exercises the helper that widens the caller dict and asserts the
expected behaviour without requiring a live database.
"""

from __future__ import annotations

import pytest

from api.mcp.tools.identity_attribution import (
    _widen_compartments,
    assert_identity_attribution,
)


class TestWidenCompartments:
    def test_none_caller_yields_max_tlp_and_compartment(self) -> None:
        widened = _widen_compartments(None, "INV-42")
        assert "INV-42" in widened["allowed_compartments"]
        # Fallback dict (caller_identity is None) ships max_tlp=4.
        assert widened["max_tlp"] == 4

    def test_existing_compartments_preserved(self) -> None:
        caller = {
            "actor": "ciso@core",
            "max_tlp": 4,
            "allowed_compartments": ["INV-1", "INV-2"],
        }
        widened = _widen_compartments(caller, "INV-3")
        assert widened["allowed_compartments"] == ["INV-1", "INV-2", "INV-3"]

    def test_idempotent_when_compartment_already_present(self) -> None:
        caller = {
            "actor": "ciso@core",
            "max_tlp": 4,
            "allowed_compartments": ["INV-9"],
        }
        widened = _widen_compartments(caller, "INV-9")
        # No duplicate, single occurrence preserved.
        assert widened["allowed_compartments"].count("INV-9") == 1

    def test_max_tlp_is_preserved_not_silently_widened(self) -> None:
        """The helper widens *compartments*, not max_tlp.

        Callers arriving below TLP:RED are rejected upstream by
        ``assert_identity_attribution``'s precondition check. The helper
        itself preserves whatever max_tlp the caller carries.
        """
        caller = {
            "actor": "soc@core",
            "max_tlp": 2,
            "allowed_compartments": [],
        }
        widened = _widen_compartments(caller, "INV-X")
        assert widened["max_tlp"] == 2

    def test_does_not_mutate_caller(self) -> None:
        caller = {
            "actor": "ciso@core",
            "max_tlp": 4,
            "allowed_compartments": ["A"],
        }
        original_compartments = list(caller["allowed_compartments"])
        original_tlp = caller["max_tlp"]
        _widen_compartments(caller, "B")
        assert caller["allowed_compartments"] == original_compartments
        assert caller["max_tlp"] == original_tlp


class TestAssertIdentityAttributionPrecondition:
    """The TLP:RED precondition must reject lower-clearance callers before
    any Cerbos or DB call. Exercises the early-return path."""

    @pytest.mark.asyncio
    async def test_rejects_caller_below_tlp_red(self) -> None:
        with pytest.raises(ValueError, match=r"max_tlp.*==.*4"):
            await assert_identity_attribution(
                principal_id="P-1",
                threat_actor_stix_id="threat-actor--1234",
                justification="test",
                investigation_id="INV-1",
                caller_identity={
                    "actor": "soc@core",
                    "max_tlp": 2,
                    "allowed_compartments": [],
                    "roles": ["soc_analyst"],
                },
            )

    @pytest.mark.asyncio
    async def test_rejects_caller_with_no_max_tlp(self) -> None:
        # Default fallback to CG_DEFAULT_TLP (which is below 4).
        with pytest.raises(ValueError, match=r"max_tlp.*==.*4"):
            await assert_identity_attribution(
                principal_id="P-1",
                threat_actor_stix_id="threat-actor--1234",
                justification="test",
                investigation_id="INV-1",
                caller_identity={"actor": "ciso@core", "roles": ["ciso"]},
            )
