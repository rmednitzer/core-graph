"""Integration test: the memory tools sync the denormalized edge tlp_level.

AGE 1.7 does not fire the 022 trg_edge_tlp_sync trigger on Cypher writes, so
the memory layer's Cypher-created edges (mentions, extracted_from, ...) would
otherwise keep the column at 0 and be visible below their TLP. tool_remember /
tool_record_extracted_fact call resync_vertex_edges() to populate it; this
drives the real tools and asserts the column is correct.
"""

from __future__ import annotations

import pytest

from tests.integration._helpers import poll_query

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


async def test_memory_mentions_edge_tlp_synced(pg_conn) -> None:
    """A mentions edge created by tool_remember must carry its TLP on the column."""
    from api.mcp.tools.memory_remember import tool_remember

    episode = await tool_remember(
        session_id="edge-tlp-mem-session",
        content="Suspicious beacon to 203.0.113.77 observed",
        caller_identity={"max_tlp": 4, "allowed_compartments": []},
        tlp_level=3,
    )

    # The IOC (203.0.113.77) becomes a ConceptEntity + a mentions edge from the
    # Episode. The denormalized column must be GREATEST(episode=3, concept=3)=3,
    # not the 0 a Cypher-only MERGE would leave. start_id is a graphid; compare
    # by text to avoid a bound-int → graphid cast.
    row = await poll_query(
        pg_conn,
        "select tlp_level from core_graph.mentions where start_id::text = %s",
        (str(episode.graph_id),),
    )
    assert row is not None, "mentions edge not created by tool_remember"
    assert int(row["tlp_level"]) == 3, (
        f"mentions edge tlp_level not synced: got {row['tlp_level']}, expected 3"
    )

    # Edge RLS keys on the column: a TLP:AMBER analyst must not see the TLP=3 edge.
    await pg_conn.execute("grant usage on schema core_graph, ag_catalog to cg_soc_analyst")
    await pg_conn.execute("grant select on core_graph.mentions to cg_soc_analyst")
    await pg_conn.execute("set role cg_soc_analyst")
    await pg_conn.execute("select set_config('app.max_tlp', '2', false)")
    try:
        cur = await pg_conn.execute(
            "select count(*) as n from core_graph.mentions where start_id::text = %s",
            (str(episode.graph_id),),
        )
        visible = await cur.fetchone()
    finally:
        await pg_conn.execute("reset role")
        await pg_conn.execute("select set_config('app.max_tlp', '4', false)")
    assert visible["n"] == 0, "TLP=3 mentions edge visible to TLP:AMBER — edge RLS not enforced"
