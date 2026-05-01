"""Tests for the AGE template-safety helpers.

The age_template module enforces an allowlist on labels and edge types
that callers may interpolate into Cypher (since AGE cannot parameterise
those positions). It also bounds path-length quantifiers.
"""

from __future__ import annotations

import pytest

from api.utils.age_template import (
    allowed_edge_labels,
    allowed_vertex_labels,
    register_edge_labels,
    register_vertex_labels,
    render_path_quantifier,
    validate_edge_label,
    validate_max_hops,
    validate_vertex_label,
)


class TestVertexLabelAllowlist:
    def test_known_vertex_label_passes(self) -> None:
        assert validate_vertex_label("Host") == "Host"

    def test_unknown_vertex_label_rejected(self) -> None:
        with pytest.raises(ValueError):
            validate_vertex_label("Quux42")

    def test_invalid_characters_rejected(self) -> None:
        with pytest.raises(ValueError):
            validate_vertex_label("Host; DROP TABLE")

    def test_register_extends_allowlist(self) -> None:
        register_vertex_labels(["TempLabelForTest"])
        assert "TempLabelForTest" in allowed_vertex_labels()
        assert validate_vertex_label("TempLabelForTest") == "TempLabelForTest"


class TestEdgeLabelAllowlist:
    def test_known_edge_label_passes(self) -> None:
        assert validate_edge_label("mentions") == "mentions"

    def test_unknown_edge_label_rejected(self) -> None:
        with pytest.raises(ValueError):
            validate_edge_label("steals")

    def test_register_extends_allowlist(self) -> None:
        register_edge_labels(["temp_edge_for_test"])
        assert "temp_edge_for_test" in allowed_edge_labels()


class TestMaxHopsBound:
    def test_in_range(self) -> None:
        assert validate_max_hops(3) == 3

    def test_zero_rejected(self) -> None:
        with pytest.raises(ValueError):
            validate_max_hops(0)

    def test_negative_rejected(self) -> None:
        with pytest.raises(ValueError):
            validate_max_hops(-1)

    def test_above_ceiling_rejected(self) -> None:
        with pytest.raises(ValueError):
            validate_max_hops(99)

    def test_custom_ceiling(self) -> None:
        with pytest.raises(ValueError):
            validate_max_hops(5, ceiling=4)

    def test_quantifier_render(self) -> None:
        assert render_path_quantifier(1, 3) == "*1..3"

    def test_quantifier_min_gt_max_rejected(self) -> None:
        with pytest.raises(ValueError):
            render_path_quantifier(4, 2)
