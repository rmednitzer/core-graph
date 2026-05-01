"""Tests for the metric helpers used by bench_retrieval_recall."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "bench" / "bench_retrieval_recall.py"

# Load the bench script as a module for direct unit testing.
_spec = importlib.util.spec_from_file_location("bench_retrieval_recall", SCRIPT)
assert _spec is not None and _spec.loader is not None
_bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_bench)


def test_recall_at_perfect() -> None:
    assert _bench._recall_at([1, 2, 3], {1, 2, 3}, 3) == 1.0


def test_recall_at_partial() -> None:
    # 2 of 3 expected docs in top-3.
    assert _bench._recall_at([1, 2, 9], {1, 2, 3}, 3) == 2 / 3


def test_recall_at_top_k_smaller_than_returned() -> None:
    assert _bench._recall_at([9, 8, 1], {1}, 2) == 0.0
    assert _bench._recall_at([9, 8, 1], {1}, 3) == 1.0


def test_reciprocal_rank_first() -> None:
    assert _bench._reciprocal_rank([1, 2, 3], {1}) == 1.0


def test_reciprocal_rank_second() -> None:
    assert _bench._reciprocal_rank([9, 1, 3], {1}) == 0.5


def test_reciprocal_rank_zero_when_missing() -> None:
    assert _bench._reciprocal_rank([9, 8], {1}) == 0.0


def test_ndcg_perfect_at_two() -> None:
    assert round(_bench._ndcg_at([1, 2], {1, 2}, 2), 4) == 1.0


def test_ndcg_drops_when_relevant_lower() -> None:
    perfect = _bench._ndcg_at([1, 2, 3], {1, 2, 3}, 3)
    swapped = _bench._ndcg_at([9, 1, 2], {1, 2}, 3)
    assert swapped < perfect


def test_ndcg_zero_when_no_expected() -> None:
    assert _bench._ndcg_at([1, 2, 3], set(), 3) == 0.0
