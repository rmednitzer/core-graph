"""Integration tests for RLS enforcement on the AGE graph (relational) tables.

A superuser bypasses RLS, so visibility is checked under a non-superuser role
(cg_soc_analyst) with an explicit app.max_tlp ceiling — the same mechanism the
TLP read policies key on.
"""

from __future__ import annotations

import json

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


async def _insert_vertex(pg_conn, value: str, tlp: int) -> None:
    """Insert a CanonicalIP vertex with a specific TLP level (as superuser)."""
    params = json.dumps({"value": value, "tlp": tlp})
    await pg_conn.execute(
        """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:CanonicalIP {value: $value})
            set v.tlp_level = $tlp
            return id(v)
        $$, %s) as (id agtype)
        """,
        (params,),
    )


async def _visible_ips(pg_conn, max_tlp: int, values: list[str]) -> set[str]:
    """CanonicalIP values visible to cg_soc_analyst at the given app.max_tlp."""
    # Table-level SELECT is granted by migration 004; schema USAGE is not (the
    # app's read path is the cg_admin superuser), so grant it here as setup.
    await pg_conn.execute("grant usage on schema core_graph, ag_catalog to cg_soc_analyst")
    await pg_conn.execute("set role cg_soc_analyst")
    await pg_conn.execute("select set_config('app.max_tlp', %s, false)", (str(max_tlp),))
    try:
        cur = await pg_conn.execute(
            "select (properties::text)::jsonb->>'value' as value "
            'from core_graph."CanonicalIP" '
            "where (properties::text)::jsonb->>'value' = any(%s)",
            (values,),
        )
        rows = await cur.fetchall()
    finally:
        await pg_conn.execute("reset role")
        await pg_conn.execute("select set_config('app.max_tlp', '4', false)")
    return {r["value"] for r in rows}


async def test_rls_filters_by_tlp(pg_conn) -> None:
    """At AMBER (max_tlp=2) a GREEN vertex is visible but a RED one is filtered."""
    await _insert_vertex(pg_conn, "203.0.113.10", 1)
    await _insert_vertex(pg_conn, "203.0.113.11", 4)

    visible = await _visible_ips(pg_conn, 2, ["203.0.113.10", "203.0.113.11"])
    assert "203.0.113.10" in visible, "GREEN vertex should be visible at TLP:AMBER"
    assert "203.0.113.11" not in visible, "RED vertex must be filtered at TLP:AMBER"


async def test_high_tlp_sees_all(pg_conn) -> None:
    """At RED (max_tlp=4) all vertices are visible."""
    await _insert_vertex(pg_conn, "203.0.113.20", 1)
    await _insert_vertex(pg_conn, "203.0.113.21", 4)

    visible = await _visible_ips(pg_conn, 4, ["203.0.113.20", "203.0.113.21"])
    assert "203.0.113.20" in visible
    assert "203.0.113.21" in visible
