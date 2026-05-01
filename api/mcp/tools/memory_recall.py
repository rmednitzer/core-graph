"""api.mcp.tools.memory_recall — Retrieve top-k Episodes for a session.

Combines the Phase-1 hybrid retrieval pipeline with the Phase-3 salience
materialised score. Steps:

  1. hybrid_search(query, k=k*4) — over-fetch.
  2. Filter to Episode vertices belonging to the session via AGE.
  3. Re-rank by `score_hybrid * 0.7 + salience * 0.3`.
  4. Return the top-k Episodes plus their hybrid score, salience, and
     bm25/vector ranks.

Bumps `access_count` and `last_accessed_at` for every returned episode so
the next salience refresh reflects this query.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from api.config import DEFAULT_TLP
from api.db import get_connection
from api.mcp.tools.hybrid_search import hybrid_search

logger = logging.getLogger(__name__)


@dataclass
class RecalledEpisode:
    graph_id: int
    session_id: str
    sequence_no: int
    content: str | None
    score: float
    hybrid_score: float
    salience: float
    bm25_rank: int | None = None
    vector_rank: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "session_id": self.session_id,
            "sequence_no": self.sequence_no,
            "content": self.content,
            "score": self.score,
            "hybrid_score": self.hybrid_score,
            "salience": self.salience,
            "bm25_rank": self.bm25_rank,
            "vector_rank": self.vector_rank,
            "metadata": self.metadata,
        }


HYBRID_WEIGHT = 0.7
SALIENCE_WEIGHT = 0.3


async def tool_recall(
    session_id: str,
    query: str,
    k: int = 10,
    *,
    ef_search: int = 100,
    caller_identity: dict[str, Any] | None = None,
) -> list[RecalledEpisode]:
    """Top-k Episodes for the session, ranked by hybrid + salience."""
    if not session_id or not query:
        raise ValueError("session_id and query are required")

    caller = caller_identity or {"max_tlp": DEFAULT_TLP, "allowed_compartments": []}
    correlation_id = uuid.uuid4()

    hits = await hybrid_search(
        query=query,
        k=max(k * 4, k),
        ef_search=ef_search,
        rerank=False,
        caller_identity=caller,
    )

    if not hits:
        return []

    candidate_ids = [h.graph_id for h in hits]

    async with get_connection(caller) as conn:
        episode_check_sql = """
            select * from ag_catalog.cypher('core_graph', $cypher$
                match (e:Episode {session_id: $session_id})
                where id(e) in $ids
                return id(e) as id, e.sequence_no as seq,
                       e.content as content, e.source_kind as source_kind
            $cypher$, %s) as (row agtype)
        """
        cur = await conn.execute(
            episode_check_sql,
            (json.dumps({"session_id": session_id, "ids": candidate_ids}),),
        )
        rows = await cur.fetchall()

        episode_meta: dict[int, dict[str, Any]] = {}
        for r in rows:
            payload = r["row"]
            if isinstance(payload, str):
                # Strip the "::vertex" agtype suffix and any trailing colon.
                if payload.endswith("::vertex"):
                    payload = payload[: -len("::vertex")]
                payload = json.loads(payload.rstrip(":"))
            if isinstance(payload, dict):
                gid = int(str(payload.get("id", "")).strip('"'))
                episode_meta[gid] = {
                    "sequence_no": int(payload.get("seq") or 0),
                    "content": payload.get("content"),
                    "source_kind": payload.get("source_kind"),
                }

        if not episode_meta:
            return []

        salience_cur = await conn.execute(
            """
            select episode_graph_id, salience
              from memory_episode_salience
             where session_id = %s
               and episode_graph_id = any(%s)
            """,
            (session_id, list(episode_meta.keys())),
        )
        salience_rows = await salience_cur.fetchall()
        salience_map = {int(r["episode_graph_id"]): float(r["salience"]) for r in salience_rows}

    fused: list[RecalledEpisode] = []
    for h in hits:
        if h.graph_id not in episode_meta:
            continue
        meta = episode_meta[h.graph_id]
        salience = salience_map.get(h.graph_id, 0.0)
        score = HYBRID_WEIGHT * h.score + SALIENCE_WEIGHT * salience
        fused.append(
            RecalledEpisode(
                graph_id=h.graph_id,
                session_id=session_id,
                sequence_no=int(meta.get("sequence_no") or 0),
                content=meta.get("content"),
                score=score,
                hybrid_score=h.score,
                salience=salience,
                bm25_rank=h.bm25_rank,
                vector_rank=h.vector_rank,
                metadata={"source_kind": meta.get("source_kind")},
            )
        )

    fused.sort(key=lambda r: r.score, reverse=True)
    out = fused[:k]

    # Bump access metrics ONLY for the episodes we actually return —
    # otherwise non-returned candidates would get salience boosts on every
    # query, biasing future recall.
    returned_ids = [r.graph_id for r in out]
    async with get_connection(caller) as conn:
        if returned_ids:
            await conn.execute(
                """
                update memory_episode_salience
                   set access_count = access_count + 1,
                       last_accessed_at = now()
                 where session_id = %s
                   and episode_graph_id = any(%s)
                """,
                (session_id, returned_ids),
            )
        await conn.execute(
            """
            insert into audit_log
                (entity_label, operation, actor, correlation_id)
            values (%s, %s, %s, %s)
            """,
            (
                "Episode",
                "MEMORY_RECALL",
                caller.get("actor", "mcp"),
                correlation_id,
            ),
        )
        await conn.commit()

    logger.info(
        "Recall: session=%s query_len=%d hits=%d returned=%d correlation=%s",
        session_id,
        len(query),
        len(hits),
        len(out),
        correlation_id,
    )
    return out
