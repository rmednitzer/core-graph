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

from api.mcp.tools.identity_attribution import _widen_compartments


class TestWidenCompartments:
    def test_none_caller_yields_max_tlp_and_compartment(self) -> None:
        widened = _widen_compartments(None, "INV-42")
        assert "INV-42" in widened["allowed_compartments"]
        assert widened["max_tlp"] >= 4

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

    def test_low_max_tlp_is_raised_to_red(self) -> None:
        caller = {
            "actor": "soc@core",
            "max_tlp": 2,
            "allowed_compartments": [],
        }
        widened = _widen_compartments(caller, "INV-X")
        assert widened["max_tlp"] >= 4

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
