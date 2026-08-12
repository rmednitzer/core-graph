"""Unit tests for the RRF fusion logic in hybrid_search.

The DB-touching code paths are exercised by integration tests; here we
verify the pure fusion function and the Hit dataclass.
"""

from __future__ import annotations

import pytest

from api.mcp.tools.hybrid_search import RRF_K, Hit, _rrf_fuse, _vector_candidates


def _row(graph_id: int, content: str = "") -> dict:
    return {"graph_id": graph_id, "label": "Doc", "content": content}


class TestRRFFuse:
    def test_doc_only_in_one_list_keeps_single_contribution(self) -> None:
        bm25 = [_row(1)]
        vec: list = []
        fused = _rrf_fuse(bm25, vec)
        assert set(fused) == {1}
        assert fused[1]["bm25_rank"] == 1
        assert fused[1]["vector_rank"] is None
        assert fused[1]["score"] == 1.0 / (RRF_K + 1)

    def test_doc_in_both_lists_sums_contributions(self) -> None:
        bm25 = [_row(1), _row(2)]
        vec = [_row(2), _row(1)]
        fused = _rrf_fuse(bm25, vec)
        # Doc 1 ranks 1 in BM25 and 2 in vector; doc 2 vice-versa.
        assert fused[1]["score"] == 1.0 / (RRF_K + 1) + 1.0 / (RRF_K + 2)
        assert fused[2]["score"] == 1.0 / (RRF_K + 2) + 1.0 / (RRF_K + 1)
        # Equal sums => same score.
        assert fused[1]["score"] == fused[2]["score"]

    def test_higher_combined_rank_wins(self) -> None:
        bm25 = [_row(1), _row(2), _row(3)]
        vec = [_row(1), _row(3), _row(2)]
        fused = _rrf_fuse(bm25, vec)
        ranked = sorted(fused.values(), key=lambda f: f["score"], reverse=True)
        assert int(ranked[0]["row"]["graph_id"]) == 1

    def test_k_constant_value(self) -> None:
        # Cormack/Clarke/Buettcher 2009 — the literature constant is 60.
        assert RRF_K == 60


class TestHit:
    def test_to_dict_round_trip(self) -> None:
        h = Hit(
            graph_id=42,
            label="ThreatActor",
            content="apt28",
            score=0.123,
            bm25_rank=1,
            vector_rank=3,
            rerank_score=0.9,
        )
        d = h.to_dict()
        assert d["graph_id"] == 42
        assert d["bm25_rank"] == 1
        assert d["vector_rank"] == 3
        assert d["rerank_score"] == 0.9


class _CapturingCursor:
    async def fetchall(self) -> list[dict]:
        return []


class _CapturingConn:
    """Records the SQL and parameters handed to execute()."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple]] = []

    async def execute(self, sql: str, params: tuple = ()) -> _CapturingCursor:
        self.calls.append((sql, params))
        return _CapturingCursor()


@pytest.mark.asyncio
class TestVectorCandidates:
    """Migration 036 moved the ANN onto the `retrieval_embeddings` serving
    tier. Two properties matter and neither is visible from RRF fusion."""

    async def test_queries_the_serving_tier_not_the_legacy_table(self) -> None:
        conn = _CapturingConn()
        await _vector_candidates(conn, [0.1, 0.2], 10, "nomic-embed-text")
        sql, _ = conn.calls[0]
        assert "retrieval_embeddings" in sql
        # The legacy full-precision column must not be what is ordered on.
        assert "::halfvec" in sql
        assert "::vector" not in sql

    async def test_ann_is_ordered_and_limited_before_the_join(self) -> None:
        """Joining first and ordering afterwards leaves the planner unable to
        use the HNSW index, which is a silent performance cliff rather than an
        error, so it is worth asserting on the query shape."""
        conn = _CapturingConn()
        await _vector_candidates(conn, [0.1, 0.2], 10, "nomic-embed-text")
        sql, _ = conn.calls[0]
        cte = sql[sql.index("with cand") : sql.index(") select")]
        assert "order by" in cte
        assert "limit" in cte
        assert "join" not in cte

    async def test_filters_on_exactly_one_model(self) -> None:
        """The per-model HNSW indexes are partial, so an unfiltered scan would
        miss every index and mix vector spaces that are not comparable."""
        conn = _CapturingConn()
        await _vector_candidates(conn, [0.1, 0.2], 10, "nomic-embed-text")
        sql, params = conn.calls[0]
        assert "where model_id = %s" in sql
        assert "nomic-embed-text" in params
