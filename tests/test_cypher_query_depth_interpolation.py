"""Tests for the depth-marker interpolation in cypher_query.

Templates marked with `template_kind: interpolated_depth` declare a marker
token (e.g. `__DEPTH__`) that is replaced with a validated integer at
load time. The unit tests below cover the rejection paths and the happy
substitution.
"""

from __future__ import annotations

import pytest

from api.mcp.tools.cypher_query import _materialise_depth


def _schemas(marker: str = "__DEPTH__", *, kind: str = "interpolated_depth") -> dict:
    return {
        "demo": {
            "template_kind": kind,
            "depth_marker": marker,
        }
    }


def test_substitutes_validated_depth() -> None:
    cypher = "match (a)-[*1..__DEPTH__]-(b) return b"
    out_cypher, out_params = _materialise_depth(
        "demo", cypher, {"depth": 3, "x": 1}, _schemas()
    )
    assert "*1..3" in out_cypher
    assert "depth" not in out_params  # consumed
    assert out_params["x"] == 1  # untouched


def test_supports_max_hops_alias() -> None:
    cypher = "match path = (a)-[*1..__M__]-(b) return path"
    out_cypher, out_params = _materialise_depth(
        "demo", cypher, {"max_hops": 5}, _schemas("__M__")
    )
    assert "*1..5" in out_cypher
    assert "max_hops" not in out_params


def test_rejects_missing_depth() -> None:
    cypher = "match (a)-[*1..__DEPTH__]-(b) return b"
    with pytest.raises(ValueError, match="requires a `depth` or `max_hops`"):
        _materialise_depth("demo", cypher, {}, _schemas())


def test_rejects_out_of_range_depth() -> None:
    cypher = "match (a)-[*1..__DEPTH__]-(b) return b"
    with pytest.raises(ValueError):
        _materialise_depth("demo", cypher, {"depth": 99}, _schemas())


def test_rejects_marker_absent_from_template() -> None:
    cypher = "match (a)-(b) return b"
    with pytest.raises(ValueError, match="depth_marker"):
        _materialise_depth("demo", cypher, {"depth": 2}, _schemas())


def test_no_op_for_non_interpolated_template() -> None:
    cypher = "match (a)-[*1..2]-(b) return b"
    out_cypher, out_params = _materialise_depth(
        "demo", cypher, {"x": 1}, _schemas(kind="standard")
    )
    assert out_cypher == cypher
    assert out_params == {"x": 1}
