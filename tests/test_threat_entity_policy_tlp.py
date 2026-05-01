"""Verify threat_entity Cerbos policy uses integer TLP encoding.

The schema, RLS policies, and adapters all use integer 0..4 for tlp_level.
Cerbos resource policies must align — string TLP comparisons (e.g.
`tlp_marking in ["RED", ...]`) are bugs.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

POLICY_PATH = (
    Path(__file__).resolve().parent.parent / "policies" / "resource" / "threat_entity.yaml"
)

# Strings we never want to see compared against TLP attrs.
_FORBIDDEN_TLP_STRINGS = ("RED", "AMBER", "AMBER+STRICT", "GREEN", "CLEAR", "WHITE")


def test_policy_file_present() -> None:
    assert POLICY_PATH.is_file(), f"Missing policy: {POLICY_PATH}"


def test_policy_uses_tlp_level_attr() -> None:
    text = POLICY_PATH.read_text()
    assert "tlp_level" in text, "Policy must reference resource.attr.tlp_level (int)"


def test_policy_does_not_use_string_tlp_marking() -> None:
    text = POLICY_PATH.read_text()
    assert "tlp_marking" not in text, (
        "Policy still references resource.attr.tlp_marking; "
        "switch to integer tlp_level to align with schema/RLS encoding."
    )


@pytest.mark.parametrize("forbidden", _FORBIDDEN_TLP_STRINGS)
def test_policy_does_not_compare_against_tlp_strings(forbidden: str) -> None:
    text = POLICY_PATH.read_text()
    # Comments and the integer-encoding key may legitimately mention these
    # words. We reject them only when they appear inside a quoted list literal,
    # which is the pattern Cerbos uses for string-based comparison.
    quoted = re.compile(rf'(["\']){re.escape(forbidden)}\1')
    matches = quoted.findall(text)
    assert not matches, (
        f"Policy contains a quoted TLP token {forbidden!r}; "
        f"TLP must be encoded as integer 0..4 only."
    )
