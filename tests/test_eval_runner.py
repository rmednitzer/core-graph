"""Unit tests for the retrieval-eval runner helpers (no DB needed)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "eval" / "run_retrieval_eval.py"

_spec = importlib.util.spec_from_file_location("run_retrieval_eval", SCRIPT)
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
# Register before exec so dataclasses can resolve the owning module.
sys.modules["run_retrieval_eval"] = _mod
_spec.loader.exec_module(_mod)


def test_load_golden_v1_has_200_pairs() -> None:
    pairs = _mod._load_golden(ROOT / "tests" / "eval" / "golden" / "retrieval_v1.jsonl")
    assert len(pairs) == 200
    categories = {p.category for p in pairs}
    assert {"threat_intel", "osint", "identity", "audit", "infrastructure"} <= categories
    tlps = {p.tlp_level for p in pairs}
    # All TLP levels 0..4 must appear.
    assert tlps >= {0, 1, 2}


def test_aggregate_handles_empty() -> None:
    out = _mod._aggregate([])
    assert out["queries"] == 0
    assert out["recall_at_5"] == 0.0


def test_aggregate_means() -> None:
    out = _mod._aggregate([
        {"r5": 1.0, "r10": 0.5, "r20": 0.5, "rr": 1.0, "ndcg10": 1.0},
        {"r5": 0.0, "r10": 0.5, "r20": 1.0, "rr": 0.5, "ndcg10": 0.5},
    ])
    assert out["queries"] == 2
    assert out["recall_at_5"] == 0.5
    assert out["recall_at_10"] == 0.5
    assert out["mrr"] == 0.75


def test_format_markdown_contains_sections() -> None:
    report = {
        "golden_path": "p",
        "queries": 1,
        "model_id": "m",
        "ef_search": 100,
        "modes": [
            {
                "mode": "vector",
                "overall": {
                    "queries": 1,
                    "recall_at_5": 1.0,
                    "recall_at_10": 1.0,
                    "recall_at_20": 1.0,
                    "mrr": 1.0,
                    "ndcg_at_10": 1.0,
                },
                "per_category": {
                    "threat_intel": {
                        "queries": 1,
                        "recall_at_5": 1.0,
                        "recall_at_10": 1.0,
                        "recall_at_20": 1.0,
                        "mrr": 1.0,
                        "ndcg_at_10": 1.0,
                    }
                },
                "per_tlp": {
                    "1": {
                        "queries": 1,
                        "recall_at_5": 1.0,
                        "recall_at_10": 1.0,
                        "recall_at_20": 1.0,
                        "mrr": 1.0,
                        "ndcg_at_10": 1.0,
                    }
                },
            }
        ],
    }
    md = _mod._format_markdown(report)
    assert "# Retrieval eval report" in md
    assert "## Overall" in md
    assert "per category" in md
    assert "per TLP level" in md


def test_recall_metrics_match_bench_implementation() -> None:
    """Both bench and eval runners must agree on the recall function."""
    bench_spec = importlib.util.spec_from_file_location(
        "bench_retrieval_recall", ROOT / "scripts" / "bench" / "bench_retrieval_recall.py"
    )
    bench = importlib.util.module_from_spec(bench_spec)
    sys.modules["bench_retrieval_recall"] = bench
    bench_spec.loader.exec_module(bench)

    expected = {1, 2, 3}
    returned = [1, 2, 9, 4]
    assert _mod._recall_at(returned, expected, 3) == bench._recall_at(returned, expected, 3)
    assert _mod._reciprocal_rank(returned, expected) == bench._reciprocal_rank(returned, expected)
    assert _mod._ndcg_at(returned, expected, 5) == bench._ndcg_at(returned, expected, 5)
