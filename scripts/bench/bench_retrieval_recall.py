"""Recall benchmark for the embeddings retrieval stack.

Loads a golden set of (query, expected_doc_ids) pairs and computes
recall@5/10/20, mean reciprocal rank, and nDCG@10 across four retrieval
modes:

  * vector-only — pgvector cosine on the full-precision column
  * bm25-only — ts_rank_cd on content_tsv
  * hybrid — RRF fusion (BM25 + vector)
  * hybrid+rerank — RRF fusion followed by an external reranker (skipped
    when CG_RERANKER_URL is unset)

Phase 5 ships a curated 200-pair set; Phase 1 ships a synthetic 100-pair
stub at tests/eval/golden/synthetic_v1.jsonl. Pass --golden to override.

Usage:
    python scripts/bench/bench_retrieval_recall.py \
        --pg-dsn postgresql://cg_admin:cg_dev_only@localhost:5432/core_graph \
        --golden tests/eval/golden/synthetic_v1.jsonl
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import statistics
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent.parent

# Allow `python scripts/bench/...` execution by ensuring the repo root is importable.
sys.path.insert(0, str(ROOT))


def _load_golden(path: Path) -> list[dict[str, Any]]:
    pairs: list[dict[str, Any]] = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            pairs.append(json.loads(line))
    return pairs


def _recall_at(returned: list[int], expected: set[int], k: int) -> float:
    if not expected:
        return 0.0
    head = set(returned[:k])
    return len(head & expected) / len(expected)


def _reciprocal_rank(returned: list[int], expected: set[int]) -> float:
    for rank, doc in enumerate(returned, start=1):
        if doc in expected:
            return 1.0 / rank
    return 0.0


def _ndcg_at(returned: list[int], expected: set[int], k: int) -> float:
    if not expected:
        return 0.0
    dcg = 0.0
    for rank, doc in enumerate(returned[:k], start=1):
        if doc in expected:
            # Binary relevance — gain = 1 / log2(rank + 1).
            dcg += 1.0 / math.log2(rank + 1)
    ideal_n = min(len(expected), k)
    idcg = sum(1.0 / math.log2(r + 1) for r in range(1, ideal_n + 1))
    return dcg / idcg if idcg > 0 else 0.0


async def _run_mode(
    mode: str,
    pairs: list[dict[str, Any]],
    *,
    model_id: str | None,
    ef_search: int,
) -> dict[str, Any]:
    """Execute every pair under one retrieval mode and aggregate metrics."""
    from api.mcp.tools.hybrid_search import hybrid_search
    from api.mcp.tools.vector_search import vector_search

    recalls: dict[int, list[float]] = {5: [], 10: [], 20: []}
    rrs: list[float] = []
    ndcgs: list[float] = []

    for pair in pairs:
        query = pair["query"]
        expected = {int(d) for d in pair["expected_doc_ids"]}

        if mode == "vector":
            rows = await vector_search(
                text=query,
                limit=20,
                model_id=model_id,
                ef_search=ef_search,
            )
            ranked = [int(r["graph_id"]) for r in rows]
        elif mode == "bm25":
            rows = await _bm25_only(query, model_id=model_id, k=20)
            ranked = [int(r["graph_id"]) for r in rows]
        elif mode == "hybrid":
            hits = await hybrid_search(
                query=query,
                k=20,
                model_id=model_id,
                ef_search=ef_search,
                rerank=False,
            )
            ranked = [h.graph_id for h in hits]
        elif mode == "hybrid_rerank":
            hits = await hybrid_search(
                query=query,
                k=20,
                model_id=model_id,
                ef_search=ef_search,
                rerank=True,
            )
            ranked = [h.graph_id for h in hits]
        else:
            raise ValueError(f"unknown mode: {mode}")

        recalls[5].append(_recall_at(ranked, expected, 5))
        recalls[10].append(_recall_at(ranked, expected, 10))
        recalls[20].append(_recall_at(ranked, expected, 20))
        rrs.append(_reciprocal_rank(ranked, expected))
        ndcgs.append(_ndcg_at(ranked, expected, 10))

    return {
        "mode": mode,
        "queries": len(pairs),
        "recall_at_5": round(statistics.fmean(recalls[5]), 4),
        "recall_at_10": round(statistics.fmean(recalls[10]), 4),
        "recall_at_20": round(statistics.fmean(recalls[20]), 4),
        "mrr": round(statistics.fmean(rrs), 4),
        "ndcg_at_10": round(statistics.fmean(ndcgs), 4),
    }


async def _bm25_only(
    query: str, *, model_id: str | None, k: int
) -> list[dict[str, Any]]:
    """Direct BM25 lookup — bypasses RRF for the bm25-only mode."""
    from api.db import get_connection

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
    params = [query, *params, k]
    async with get_connection() as conn:
        cursor = await conn.execute(sql, params)
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


def _format_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Retrieval recall benchmark",
        "",
        f"- Golden set: `{report['golden_path']}` ({report['queries']} queries)",
        f"- Model: `{report['model_id'] or '*'}`",
        f"- ef_search: {report['ef_search']}",
        "",
        "| Mode | recall@5 | recall@10 | recall@20 | MRR | nDCG@10 |",
        "|------|---------:|----------:|----------:|----:|--------:|",
    ]
    for entry in report["modes"]:
        lines.append(
            f"| {entry['mode']} | {entry['recall_at_5']} | {entry['recall_at_10']} | "
            f"{entry['recall_at_20']} | {entry['mrr']} | {entry['ndcg_at_10']} |"
        )
    return "\n".join(lines) + "\n"


async def _amain(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Recall benchmark")
    parser.add_argument(
        "--pg-dsn",
        default=os.environ.get(
            "CG_PG_DSN",
            "postgresql://cg_admin:cg_dev_only@localhost:5432/core_graph",
        ),
    )
    parser.add_argument(
        "--golden",
        default=str(ROOT / "tests" / "eval" / "golden" / "synthetic_v1.jsonl"),
    )
    parser.add_argument("--model-id", default=os.environ.get("CG_EMBEDDING_MODEL"))
    parser.add_argument("--ef-search", type=int, default=100)
    parser.add_argument(
        "--modes",
        default="vector,bm25,hybrid,hybrid_rerank",
        help="Comma-separated subset of vector,bm25,hybrid,hybrid_rerank",
    )
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    os.environ.setdefault("CG_PG_DSN", args.pg_dsn)

    from api.db import close_pool, open_pool

    pairs = _load_golden(Path(args.golden))
    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    if "hybrid_rerank" in modes and not os.environ.get("CG_RERANKER_URL"):
        modes = [m for m in modes if m != "hybrid_rerank"]
        print(
            "skipping hybrid_rerank mode (CG_RERANKER_URL not set)",
            file=sys.stderr,
        )

    await open_pool()
    try:
        results = []
        for mode in modes:
            results.append(
                await _run_mode(
                    mode,
                    pairs,
                    model_id=args.model_id,
                    ef_search=args.ef_search,
                )
            )
    finally:
        await close_pool()

    report = {
        "benchmark": "retrieval_recall",
        "golden_path": args.golden,
        "queries": len(pairs),
        "model_id": args.model_id,
        "ef_search": args.ef_search,
        "modes": results,
    }
    if args.markdown:
        print(_format_markdown(report))
    else:
        print(json.dumps(report, indent=2))
    return 0


def main() -> int:
    return asyncio.run(_amain())


if __name__ == "__main__":
    raise SystemExit(main())
