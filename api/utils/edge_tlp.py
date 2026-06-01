"""api.utils.edge_tlp — keep the denormalized edge ``tlp_level`` column truthful.

Apache AGE 1.7 executes Cypher through its own executor, which bypasses the
per-table triggers (migration 022's ``trg_edge_tlp_sync`` /
``trg_vertex_tlp_cascade``). Every edge written via ``ag_catalog.cypher()``
therefore leaves the relational ``tlp_level`` column edge RLS filters on at its
``0`` default — making the edge visible below its endpoints' TLP. A plain SQL
write *does* fire the trigger, so any code path that creates or re-classifies
edges via Cypher must call one of these helpers afterwards to populate the
column. See migration ``032_edge_tlp_writer_resync.sql``.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from psycopg import sql

from api.utils.cypher_safety import validate_label


async def sync_edges_tlp(conn: Any, edge_label: str, edge_ids: Iterable[int]) -> None:
    """Re-derive ``tlp_level`` for specific edges by firing the BEFORE trigger.

    A no-op SQL ``UPDATE`` on each edge fires ``trg_edge_tlp_sync``, which
    recomputes the column as ``GREATEST`` of the edge property and both
    endpoint TLPs. ``edge_label`` must be an edge label that carries the 022
    denormalized column (every label the callers pass does); it is validated
    before interpolation as a table identifier. graphid has no cast from a
    bound integer, so it is built from its input function on the controlled
    edge id rendered as a literal (keeping the ``id`` index usable).
    """
    label = validate_label(edge_label)
    for edge_id in edge_ids:
        await conn.execute(
            sql.SQL(
                "update core_graph.{tbl} set tlp_level = tlp_level "
                "where id = {eid}::ag_catalog.graphid"
            ).format(
                tbl=sql.Identifier(label),
                eid=sql.Literal(str(int(edge_id))),
            )
        )


async def resync_vertex_edges(conn: Any, vertex_id: int) -> None:
    """Re-derive ``tlp_level`` for every edge incident to a vertex.

    Calls the ``cg_resync_vertex_edges`` SQL helper (migration 032), which
    short-circuits on a single indexed probe when the vertex has no edges. Use
    this when the caller holds an endpoint vertex id rather than the edge ids
    (and for the re-classification cascade, where an endpoint's TLP just rose).
    """
    await conn.execute(
        sql.SQL("select cg_resync_vertex_edges({}::ag_catalog.graphid)").format(
            sql.Literal(str(int(vertex_id)))
        )
    )
