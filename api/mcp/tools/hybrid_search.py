"""api.mcp.tools.hybrid_search — BM25 + vector retrieval with RRF fusion.

Combines two ranked candidate lists from PostgreSQL:

  * BM25-style lexical via `ts_rank_cd` over the `embeddings.content_tsv` GIN
    index added by migration 021.
  * Cosine similarity via pgvector's HNSW over the `retrieval_embeddings`
    serving tier added by migration 036: one native halfvec per
    (graph_id, model_id), populated only for retrieval-active subjects, with
    one partial index per model. `model_id` is resolved to a concrete model
    before either query runs, since the indexes are partial and vector spaces
    from different models are not comparable.

Reciprocal Rank Fusion (RRF) merges them with the canonical
`1 / (k + rank)` weighting (k=60). An optional reranker hook calls a local
embedding endpoint when `CG_RERANKER_URL` is set; absent => RRF only.

Function signature (per Phase 1 spec):
    async def hybrid_search(
        query: str,
        k: int = 20,
        model_id: str | None = None,
        ef_search: int = 100,
        rerank: bool = False,
    ) -> list[Hit]
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any

from api.config import DEFAULT_TLP, EMBEDDING_MODEL
from api.db import get_connection
from api.mcp.tools.vector_search import generate_embedding

logger = logging.getLogger(__name__)

# RRF constant — original Cormack/Clarke/Buettcher 2009 paper uses 60.
RRF_K = 60

# Pull each constituent list at this multiple of the requested k. Wider lists
# improve fusion quality at the cost of slightly more network bytes.
CANDIDATE_FETCH_MULTIPLIER = 4

RERANKER_URL = os.environ.get("CG_RERANKER_URL")


@dataclass
class Hit:
    """A single hybrid retrieval result."""

    graph_id: int
    label: str
    content: str | None
    score: float
    bm25_rank: int | None
    vector_rank: int | None
    rerank_score: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "label": self.label,
            "content": self.content,
            "score": self.score,
            "bm25_rank": self.bm25_rank,
            "vector_rank": self.vector_rank,
            "rerank_score": self.rerank_score,
        }


def _rrf_fuse(
    bm25: list[dict[str, Any]],
    vector: list[dict[str, Any]],
    k: int = RRF_K,
) -> dict[int, dict[str, Any]]:
    """Reciprocal Rank Fusion: score = sum_l 1 / (k + rank_l)."""
    fused: dict[int, dict[str, Any]] = {}
    for rank, row in enumerate(bm25, start=1):
        gid = int(row["graph_id"])
        fused.setdefault(
            gid,
            {"row": row, "score": 0.0, "bm25_rank": None, "vector_rank": None},
        )
        fused[gid]["score"] += 1.0 / (k + rank)
        fused[gid]["bm25_rank"] = rank

    for rank, row in enumerate(vector, start=1):
        gid = int(row["graph_id"])
        fused.setdefault(
            gid,
            {"row": row, "score": 0.0, "bm25_rank": None, "vector_rank": None},
        )
        fused[gid]["score"] += 1.0 / (k + rank)
        fused[gid]["vector_rank"] = rank
    return fused


async def _bm25_candidates(
    conn: Any,
    query: str,
    limit: int,
    model_id: str | None,
) -> list[dict[str, Any]]:
    """tsquery-based lexical retrieval. Returns at most `limit` rows."""
    where = ["content_tsv @@ plainto_tsquery('simple', %s)"]
    params: list[Any] = [query]
    if model_id is not None:
        where.append("model_id = %s")
        params.append(model_id)
    sql = (
        "select graph_id, label, content, "
        "       ts_rank_cd(content_tsv, plainto_tsquery('simple', %s)) as score "
        "from embeddings "
        f"where {' and '.join(where)} "
        "order by score desc "
        "limit %s"
    )
    params = [query, *params, limit]
    cursor = await conn.execute(sql, params)
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def _vector_candidates(
    conn: Any,
    query_vector: list[float],
    limit: int,
    model_id: str,
) -> list[dict[str, Any]]:
    """HNSW cosine-distance retrieval over the serving tier.

    Reads `retrieval_embeddings` (migration 036), which stores one native
    halfvec per (graph_id, model_id) and only for retrieval-active subjects.
    `embeddings` is joined afterwards purely to hydrate label and content.

    The ANN runs in its own CTE with its own ORDER BY and LIMIT directly
    against the indexed table. Joining first and ordering afterwards would
    leave the planner unable to use the HNSW index at all.

    `model_id` is always supplied by the caller, never None: the per-model
    indexes are partial (`where model_id = ...`), so an unfiltered scan would
    both miss every index and mix vector spaces that are not comparable.
    """
    qv = str(query_vector)
    sql = (
        "with cand as ("
        "  select graph_id, model_id, embedding <=> %s::halfvec as distance"
        "    from retrieval_embeddings"
        "   where model_id = %s"
        "   order by embedding <=> %s::halfvec"
        "   limit %s"
        ") "
        "select e.graph_id, e.label, e.content, c.distance "
        "from cand c "
        "join embeddings e "
        "  on e.graph_id = c.graph_id and e.model_id = c.model_id "
        "order by c.distance"
    )
    cursor = await conn.execute(sql, (qv, model_id, qv, limit))
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def _call_reranker(
    query: str,
    candidates: list[dict[str, Any]],
) -> list[float] | None:
    """Score candidates with the configured reranker; None if unavailable."""
    if not RERANKER_URL:
        return None
    try:
        import httpx

        payload = {
            "query": query,
            "documents": [c.get("content") or "" for c in candidates],
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(RERANKER_URL, json=payload)
            resp.raise_for_status()
            body = resp.json()
            scores = body.get("scores")
            if not isinstance(scores, list) or len(scores) != len(candidates):
                logger.warning(
                    "Reranker returned malformed payload (got %d scores for %d candidates)",
                    len(scores) if isinstance(scores, list) else -1,
                    len(candidates),
                )
                return None
            return [float(s) for s in scores]
    except Exception:
        logger.warning("Reranker unreachable, falling back to RRF only", exc_info=True)
        return None


async def hybrid_search(
    query: str,
    k: int = 20,
    model_id: str | None = None,
    ef_search: int = 100,
    rerank: bool = False,
    *,
    caller_identity: dict[str, Any] | None = None,
) -> list[Hit]:
    """Run BM25 + vector retrieval, fuse with RRF, optionally rerank.

    Returns up to `k` Hit records ordered by fused score (descending).

    When `model_id` is supplied it must match the process-default
    `CG_EMBEDDING_MODEL`. Mixed-model retrieval (generating the query
    vector with one model while filtering against rows from another) puts
    the query in a different embedding space from the candidates and
    yields invalid scores — or fails outright if dimensions differ.
    Multi-model query-time embedding generation is future work; for now
    we refuse the unsafe combination explicitly.
    """
    if not query:
        raise ValueError("hybrid_search requires a non-empty query string")

    if model_id is not None and model_id != EMBEDDING_MODEL:
        raise ValueError(
            f"hybrid_search refuses cross-model retrieval: model_id={model_id!r} "
            f"does not match the process-default embedding model {EMBEDDING_MODEL!r}. "
            "Generating the query vector with a different model puts it in a "
            "different embedding space from the candidate rows."
        )

    correlation_id = uuid.uuid4()
    caller = caller_identity or {"max_tlp": DEFAULT_TLP, "allowed_compartments": []}

    fetch_n = max(k * CANDIDATE_FETCH_MULTIPLIER, k)

    query_vector, _ = await generate_embedding(query)

    t_start = time.perf_counter()

    async with get_connection(caller) as conn:
        await conn.execute(
            "select set_config('hnsw.ef_search', %s, true)",
            (str(int(ef_search)),),
        )

        # Resolve to a concrete model rather than leaving it None. The guard
        # above already refuses cross-model retrieval, so the process default
        # is the only value None can mean; making it explicit is what lets the
        # partial per-model HNSW indexes from 036 be used at all.
        effective_model = model_id or EMBEDDING_MODEL

        bm25_rows = await _bm25_candidates(conn, query, fetch_n, effective_model)
        vector_rows = await _vector_candidates(conn, query_vector, fetch_n, effective_model)

        await conn.execute(
            """
            insert into audit_log
                (entity_label, operation, actor, correlation_id)
            values (%s, %s, %s, %s)
            """,
            (
                "hybrid_search",
                "SEARCH",
                caller_identity.get("actor", "mcp") if caller_identity else "mcp",
                correlation_id,
            ),
        )
        await conn.commit()

    fused = _rrf_fuse(bm25_rows, vector_rows, RRF_K)

    ranked = sorted(fused.values(), key=lambda f: f["score"], reverse=True)[: k * 2]

    rerank_scores: list[float] | None = None
    if rerank:
        candidate_rows = [item["row"] for item in ranked]
        rerank_scores = await _call_reranker(query, candidate_rows)

    if rerank_scores is not None:
        scored = list(zip(ranked, rerank_scores, strict=False))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        ranked = [{**item, "rerank_score": float(score)} for item, score in scored]

    hits: list[Hit] = []
    for entry in ranked[:k]:
        row = entry["row"]
        hits.append(
            Hit(
                graph_id=int(row["graph_id"]),
                label=row.get("label", ""),
                content=row.get("content"),
                score=float(entry["score"]),
                bm25_rank=entry.get("bm25_rank"),
                vector_rank=entry.get("vector_rank"),
                rerank_score=entry.get("rerank_score"),
            )
        )

    elapsed_ms = (time.perf_counter() - t_start) * 1000
    logger.info(
        "Hybrid search: correlation=%s bm25=%d vector=%d fused=%d "
        "returned=%d rerank=%s elapsed_ms=%.1f",
        correlation_id,
        len(bm25_rows),
        len(vector_rows),
        len(fused),
        len(hits),
        rerank,
        elapsed_ms,
    )
    return hits
