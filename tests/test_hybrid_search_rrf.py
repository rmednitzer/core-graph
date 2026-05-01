"""Unit tests for the RRF fusion logic in hybrid_search.

The DB-touching code paths are exercised by integration tests; here we
verify the pure fusion function and the Hit dataclass.
"""

from __future__ import annotations

from api.mcp.tools.hybrid_search import RRF_K, Hit, _rrf_fuse


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
