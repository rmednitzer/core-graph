"""Unit tests for the AI memory layer (Phase 3).

DB-touching code paths are exercised by integration tests; here we cover
the parts that are pure logic:
  * salience formula constants are loaded from config
  * subject/predicate hashing is stable
  * RecalledEpisode / SessionContext serialise correctly
"""

from __future__ import annotations

from api import config
from api.mcp.tools.memory_recall import HYBRID_WEIGHT, SALIENCE_WEIGHT, RecalledEpisode
from api.mcp.tools.memory_remember import fact_subject_predicate_hash
from api.mcp.tools.memory_session_start import SessionContext


class TestSalienceConfig:
    def test_constants_present(self) -> None:
        for name in (
            "SALIENCE_RECENCY_WEIGHT",
            "SALIENCE_ACCESS_WEIGHT",
            "SALIENCE_RELEVANCE_WEIGHT",
            "SALIENCE_DECAY",
        ):
            assert hasattr(config, name), f"config missing {name}"

    def test_weights_default_to_published_values(self) -> None:
        assert config.SALIENCE_RECENCY_WEIGHT == 0.5
        assert config.SALIENCE_ACCESS_WEIGHT == 0.2
        assert config.SALIENCE_RELEVANCE_WEIGHT == 0.3

    def test_decay_is_one_day_half_life(self) -> None:
        # 1/86400 — i.e. exp(-decay * 86400) ≈ 1/e at one-day age.
        assert abs(config.SALIENCE_DECAY - (1.0 / 86400.0)) < 1e-9

    def test_recall_weights_sum_close_to_one(self) -> None:
        assert abs((HYBRID_WEIGHT + SALIENCE_WEIGHT) - 1.0) < 1e-6


class TestFactHashing:
    def test_deterministic(self) -> None:
        s1, p1 = fact_subject_predicate_hash("apt28", "uses_tool")
        s2, p2 = fact_subject_predicate_hash("apt28", "uses_tool")
        assert s1 == s2
        assert p1 == p2

    def test_distinct(self) -> None:
        s, p = fact_subject_predicate_hash("apt28", "uses_tool")
        assert s != p

    def test_case_sensitivity(self) -> None:
        s_lower, _ = fact_subject_predicate_hash("apt28", "x")
        s_upper, _ = fact_subject_predicate_hash("APT28", "x")
        # The hash function is case-sensitive — entity resolution upstream
        # is responsible for canonicalising.
        assert s_lower != s_upper


class TestRecalledEpisode:
    def test_to_dict_round_trip(self) -> None:
        e = RecalledEpisode(
            graph_id=1,
            session_id="s1",
            sequence_no=3,
            content="hello",
            score=0.9,
            hybrid_score=0.6,
            salience=0.3,
            bm25_rank=1,
            vector_rank=2,
        )
        d = e.to_dict()
        assert d["graph_id"] == 1
        assert d["score"] == 0.9
        assert d["bm25_rank"] == 1
        assert d["vector_rank"] == 2
        assert d["metadata"] == {}


class TestSessionContext:
    def test_to_dict_includes_top_level_keys(self) -> None:
        ctx = SessionContext(
            session_id="abc",
            started_at=None,
            last_episode_at=None,
        )
        d = ctx.to_dict()
        for key in ("session_id", "recent_episodes", "active_facts", "top_entities"):
            assert key in d
