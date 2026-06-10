"""Integration execution tests for the label(v) = $label query templates (C-02).

The 2026-05 audits deferred this twice for want of a live AGE container: the
``count_entities_by_label`` and ``get_entity_by_label_and_value`` templates
compare ``label(v)`` against a *bound parameter*, which only a real AGE
execution can prove (agtype string comparison semantics differ from SQL).
"""

from __future__ import annotations

import json

import pytest

from api.mcp.tools.cypher_query import cypher_query

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

_CALLER = {
    "actor": "integration-test",
    "max_tlp": 4,
    "allowed_compartments": [],
    "roles": ["ciso"],
}

_IP = "198.51.100.77"


async def _seed_ip(pg_conn) -> None:
    await pg_conn.execute(
        f"""
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:CanonicalIP {{value: '{_IP}'}})
            set v.tlp_level = 1
            return id(v)
        $$) as (id agtype)
        """
    )


async def test_count_entities_by_label_executes_and_counts(pg_conn) -> None:
    await _seed_ip(pg_conn)
    rows = await cypher_query("count_entities_by_label", {"label": "CanonicalIP"}, _CALLER)
    assert len(rows) == 1
    count = int(str(rows[0]["result"]).strip('"'))
    assert count >= 1, "label(v) = $label must match the seeded CanonicalIP"


async def test_count_entities_by_label_filters_other_labels(pg_conn) -> None:
    # CausalChain has a vlabel (002) but nothing ever writes it; a non-zero
    # count would mean label(v) = $label is not actually filtering.
    rows = await cypher_query("count_entities_by_label", {"label": "CausalChain"}, _CALLER)
    count = int(str(rows[0]["result"]).strip('"'))
    assert count == 0, "label(v) = $label must not match vertices of other labels"


async def test_get_entity_by_label_and_value_round_trips(pg_conn) -> None:
    await _seed_ip(pg_conn)
    rows = await cypher_query(
        "get_entity_by_label_and_value", {"label": "CanonicalIP", "value": _IP}, _CALLER
    )
    assert rows, "seeded entity must be retrievable by (label, value)"
    vertex = json.loads(str(rows[0]["result"]).removesuffix("::vertex"))
    assert vertex["label"] == "CanonicalIP"
    assert vertex["properties"]["value"] == _IP

    # The same value under a different label must not match.
    rows = await cypher_query(
        "get_entity_by_label_and_value", {"label": "CanonicalDomain", "value": _IP}, _CALLER
    )
    assert rows == [], "label filter must exclude same-valued vertices of other labels"
