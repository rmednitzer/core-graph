"""Continuous-quality eval runner for the retrieval stack.

Reads tests/eval/golden/retrieval_v1.jsonl (200 hand-curated query/doc
pairs across threat_intel / osint / identity / audit / infrastructure
verticals at TLP levels 0..4), runs each query through every retrieval
mode, and emits per-category and per-TLP recall / MRR / nDCG@10.

Outputs:
  * JSON to stdout (machine-readable, CI consumes this)
  * Markdown report to --report-md (default: eval-report.md)

Hooked into nightly CI via .github/workflows/eval.yml; failure modes are
documented in the workflow.
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import json
import math
import os
import statistics
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

DEFAULT_GOLDEN = ROOT / "tests" / "eval" / "golden" / "retrieval_v1.jsonl"


@dataclass
class Pair:
    query: str
    expected_doc_ids: set[int]
    tlp_level: int
    category: str


def _load_golden(path: Path) -> list[Pair]:
    out: list[Pair] = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            out.append(
                Pair(
                    query=obj["query"],
                    expected_doc_ids={int(x) for x in obj["expected_doc_ids"]},
                    tlp_level=int(obj.get("tlp_level", 1)),
                    category=str(obj.get("category", "uncategorised")),
                )
            )
    return out


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
    dcg = sum(
        1.0 / math.log2(rank + 1)
        for rank, doc in enumerate(returned[:k], start=1)
        if doc in expected
    )
    idcg = sum(1.0 / math.log2(r + 1) for r in range(1, min(len(expected), k) + 1))
    return dcg / idcg if idcg > 0 else 0.0


async def _run_query(
    pair: Pair,
    mode: str,
    *,
    k: int,
    ef_search: int,
    model_id: str | None,
) -> list[int]:
    """Execute one query under one mode and return ranked graph_ids."""
    from api.mcp.tools.hybrid_search import hybrid_search
    from api.mcp.tools.vector_search import vector_search

    caller = {"max_tlp": pair.tlp_level, "allowed_compartments": []}

    if mode == "vector":
        rows = await vector_search(
            text=pair.query,
            limit=k,
            model_id=model_id,
            ef_search=ef_search,
            caller_identity=caller,
        )
        return [int(r["graph_id"]) for r in rows]
    elif mode == "hybrid":
        hits = await hybrid_search(
            query=pair.query,
            k=k,
            model_id=model_id,
            ef_search=ef_search,
            rerank=False,
            caller_identity=caller,
        )
        return [h.graph_id for h in hits]
    elif mode == "hybrid_rerank":
        hits = await hybrid_search(
            query=pair.query,
            k=k,
            model_id=model_id,
            ef_search=ef_search,
            rerank=True,
            caller_identity=caller,
        )
        return [h.graph_id for h in hits]
    else:
        raise ValueError(f"unknown mode: {mode}")


def _aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(records)
    if n == 0:
        return {
            "queries": 0,
            "recall_at_5": 0.0,
            "recall_at_10": 0.0,
            "recall_at_20": 0.0,
            "mrr": 0.0,
            "ndcg_at_10": 0.0,
        }
    return {
        "queries": n,
        "recall_at_5": round(statistics.fmean(r["r5"] for r in records), 4),
        "recall_at_10": round(statistics.fmean(r["r10"] for r in records), 4),
        "recall_at_20": round(statistics.fmean(r["r20"] for r in records), 4),
        "mrr": round(sum(r["rr"] for r in records) / n, 4),
        "ndcg_at_10": round(sum(r["ndcg10"] for r in records) / n, 4),
    }


async def _eval_mode(
    mode: str,
    pairs: list[Pair],
    *,
    ef_search: int,
    model_id: str | None,
) -> dict[str, Any]:
    per_category: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    per_tlp: dict[int, list[dict[str, Any]]] = collections.defaultdict(list)
    overall: list[dict[str, Any]] = []

    for pair in pairs:
        ranked = await _run_query(pair, mode, k=20, ef_search=ef_search, model_id=model_id)
        rec = {
            "r5": _recall_at(ranked, pair.expected_doc_ids, 5),
            "r10": _recall_at(ranked, pair.expected_doc_ids, 10),
            "r20": _recall_at(ranked, pair.expected_doc_ids, 20),
            "rr": _reciprocal_rank(ranked, pair.expected_doc_ids),
            "ndcg10": _ndcg_at(ranked, pair.expected_doc_ids, 10),
        }
        overall.append(rec)
        per_category[pair.category].append(rec)
        per_tlp[pair.tlp_level].append(rec)

    return {
        "mode": mode,
        "overall": _aggregate(overall),
        "per_category": {cat: _aggregate(recs) for cat, recs in per_category.items()},
        "per_tlp": {str(level): _aggregate(recs) for level, recs in per_tlp.items()},
    }


def _format_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Retrieval eval report",
        "",
        f"- Golden set: `{report['golden_path']}` ({report['queries']} queries)",
        f"- Model: `{report['model_id'] or '*'}`",
        f"- ef_search: {report['ef_search']}",
        "",
        "## Overall",
        "",
        "| Mode | recall@5 | recall@10 | recall@20 | MRR | nDCG@10 |",
        "|------|---------:|----------:|----------:|----:|--------:|",
    ]
    for entry in report["modes"]:
        o = entry["overall"]
        lines.append(
            f"| {entry['mode']} | {o['recall_at_5']} | {o['recall_at_10']} | "
            f"{o['recall_at_20']} | {o['mrr']} | {o['ndcg_at_10']} |"
        )

    for entry in report["modes"]:
        lines.extend(
            [
                "",
                f"## {entry['mode']} — per category",
                "",
                "| Category | queries | recall@10 | MRR | nDCG@10 |",
                "|----------|--------:|----------:|----:|--------:|",
            ]
        )
        for cat, m in sorted(entry["per_category"].items()):
            lines.append(
                f"| {cat} | {m['queries']} | {m['recall_at_10']} | {m['mrr']} | {m['ndcg_at_10']} |"
            )

        lines.extend(
            [
                "",
                f"## {entry['mode']} — per TLP level",
                "",
                "| tlp_level | queries | recall@10 | MRR | nDCG@10 |",
                "|----------:|--------:|----------:|----:|--------:|",
            ]
        )
        for tlp_str in sorted(entry["per_tlp"].keys(), key=int):
            m = entry["per_tlp"][tlp_str]
            lines.append(
                f"| {tlp_str} | {m['queries']} | {m['recall_at_10']} | "
                f"{m['mrr']} | {m['ndcg_at_10']} |"
            )
    return "\n".join(lines) + "\n"


async def _amain(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Retrieval eval runner")
    parser.add_argument("--golden", default=str(DEFAULT_GOLDEN))
    parser.add_argument("--model-id", default=os.environ.get("CG_EMBEDDING_MODEL"))
    parser.add_argument("--ef-search", type=int, default=100)
    parser.add_argument(
        "--modes",
        default="vector,hybrid,hybrid_rerank",
        help="Comma-separated subset of vector,hybrid,hybrid_rerank",
    )
    parser.add_argument("--report-md", default="eval-report.md")
    parser.add_argument(
        "--pg-dsn",
        default=os.environ.get(
            "CG_PG_DSN",
            "postgresql://cg_admin:cg_dev_only@localhost:5432/core_graph",
        ),
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    os.environ["CG_PG_DSN"] = args.pg_dsn

    pairs = _load_golden(Path(args.golden))
    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    if "hybrid_rerank" in modes and not os.environ.get("CG_RERANKER_URL"):
        modes = [m for m in modes if m != "hybrid_rerank"]
        print(
            "skipping hybrid_rerank mode (CG_RERANKER_URL not set)",
            file=sys.stderr,
        )

    # Every retrieval mode embeds the query, so the eval cannot run without an
    # embedding provider. CI runs this against a migrations+seeds DB with no
    # backend (CG_EMBEDDING_PROVIDER defaults to "none"); emit an explicit
    # "skipped" report and exit 0 rather than crash — the same graceful posture
    # the drift detector takes when there are no embeddings to sample.
    from api import config

    if config.EMBEDDING_PROVIDER == "none":
        report = {
            "benchmark": "retrieval_eval",
            "golden_path": args.golden,
            "queries": len(pairs),
            "model_id": args.model_id,
            "ef_search": args.ef_search,
            "status": "skipped_no_embedding_provider",
            "modes": [],
        }
        Path(args.report_md).write_text(
            "# Retrieval eval report\n\n"
            "Skipped: no embedding provider configured "
            "(`CG_EMBEDDING_PROVIDER=none`). Set a provider to run the eval.\n"
        )
        print(json.dumps(report, indent=2))
        return 0

    from api.db import close_pool, open_pool

    await open_pool()
    try:
        results = []
        for mode in modes:
            results.append(
                await _eval_mode(
                    mode,
                    pairs,
                    ef_search=args.ef_search,
                    model_id=args.model_id,
                )
            )
    finally:
        await close_pool()

    report = {
        "benchmark": "retrieval_eval",
        "golden_path": args.golden,
        "queries": len(pairs),
        "model_id": args.model_id,
        "ef_search": args.ef_search,
        "modes": results,
    }

    Path(args.report_md).write_text(_format_markdown(report))
    print(json.dumps(report, indent=2))
    return 0


def main() -> int:
    return asyncio.run(_amain())


if __name__ == "__main__":
    raise SystemExit(main())
