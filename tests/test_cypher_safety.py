"""Tests for Cypher label validation."""

import pytest

from api.utils.cypher_safety import validate_label


class TestValidateLabel:
    def test_valid_labels(self) -> None:
        assert validate_label("CanonicalIP") == "CanonicalIP"
        assert validate_label("ThreatActor") == "ThreatActor"
        assert validate_label("_private") == "_private"
        assert validate_label("A") == "A"

    def test_rejects_empty(self) -> None:
        with pytest.raises(ValueError):
            validate_label("")

    def test_rejects_leading_digit(self) -> None:
        with pytest.raises(ValueError):
            validate_label("1BadLabel")

    def test_rejects_special_characters(self) -> None:
        with pytest.raises(ValueError):
            validate_label("Label; DROP TABLE")

    def test_rejects_cypher_injection(self) -> None:
        with pytest.raises(ValueError):
            validate_label("Label`)-[]->(x")

    def test_rejects_spaces(self) -> None:
        with pytest.raises(ValueError):
            validate_label("My Label")

    def test_rejects_over_63_chars(self) -> None:
        with pytest.raises(ValueError):
            validate_label("A" * 64)

    def test_accepts_exactly_63_chars(self) -> None:
        label = "A" * 63
        assert validate_label(label) == label
