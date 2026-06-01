"""RLS-aware retrieval correctness — hard fail in CI when broken.

For every TLP level the golden set spans, run a representative slice of
queries with `caller.max_tlp = level` and assert that every returned
document's `tlp_level` is at most that ceiling. We also assert that no
query returns expected documents whose `tlp_level` exceeds the caller's
ceiling — those should be RLS-filtered.

This test is a **hard CI fail** if RLS regresses. It is intentionally
sceptical of the retrieval pipeline: even if the application layer is
broken, the RLS engine should drop above-ceiling rows.

Marked `pytest.mark.integration` since it requires a running database
populated from the golden set. The non-integration path skips.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

GOLDEN = Path(__file__).resolve().parent / "golden" / "retrieval_v1.jsonl"

pytestmark = pytest.mark.integration


def _load_golden() -> list[dict]:
    rows = []
    with GOLDEN.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def _stack_running() -> bool:
    if not os.environ.get("CG_PG_DSN"):
        return False
    try:
        import psycopg

        with psycopg.connect(os.environ["CG_PG_DSN"]) as conn:
            conn.execute("select 1")
        return True
    except Exception:
        return False


def _embeddings_available() -> bool:
    """Vector/hybrid search needs an embedding backend to embed the query."""
    try:
        from api.config import EMBEDDING_PROVIDER

        return EMBEDDING_PROVIDER != "none"
    except Exception:
        return False


if not _stack_running():
    pytest.skip("Stack not running; RLS correctness test skipped", allow_module_level=True)

if not _embeddings_available():
    pytest.skip(
        "No embedding provider (CG_EMBEDDING_PROVIDER=none); retrieval-correctness "
        "needs vector search. RLS itself is covered by tests/rls/.",
        allow_module_level=True,
    )


@pytest.fixture(scope="module")
def golden() -> list[dict]:
    return _load_golden()


@pytest.mark.asyncio
@pytest.mark.parametrize("ceiling", [0, 1, 2, 3, 4])
async def test_no_results_above_ceiling(ceiling: int, golden: list[dict]) -> None:
    """Every returned doc must have tlp_level <= caller's ceiling."""
    import psycopg

    from api.mcp.tools.vector_search import vector_search

    sample = [g for g in golden if g["tlp_level"] <= ceiling][:10]
    for entry in sample:
        rows = await vector_search(
            text=entry["query"],
            limit=20,
            caller_identity={"max_tlp": ceiling, "allowed_compartments": []},
        )
        for r in rows:
            tlp = int(r.get("tlp_level", -1)) if isinstance(r, dict) else -1
            if tlp < 0:
                # tlp not exposed on the row directly — fetch by graph_id.
                with psycopg.connect(os.environ["CG_PG_DSN"]) as conn:
                    cur = conn.execute(
                        """
                        select coalesce(((properties::text)::jsonb->>'tlp_level')::int, 0) as tlp
                          from core_graph._ag_label_vertex
                         where id = %s
                        """,
                        (int(r["graph_id"]),),
                    )
                    row = cur.fetchone()
                    tlp = int(row[0]) if row else -1
            assert tlp <= ceiling, (
                f"RLS leak: caller max_tlp={ceiling} got doc with tlp={tlp} "
                f"(query={entry['query']!r}, doc={r.get('graph_id')})"
            )


@pytest.mark.asyncio
async def test_above_ceiling_docs_are_invisible(golden: list[dict]) -> None:
    """A query whose expected docs are TLP=4 must return nothing for max_tlp=0."""
    from api.mcp.tools.vector_search import vector_search

    high_tlp_pairs = [g for g in golden if g["tlp_level"] >= 3][:5]
    for entry in high_tlp_pairs:
        rows = await vector_search(
            text=entry["query"],
            limit=20,
            caller_identity={"max_tlp": 0, "allowed_compartments": []},
        )
        expected = set(int(d) for d in entry["expected_doc_ids"])
        returned_expected = {int(r["graph_id"]) for r in rows} & expected
        assert not returned_expected, (
            f"RLS leak: max_tlp=0 caller saw expected doc(s) {returned_expected} "
            f"that should be RLS-filtered (query={entry['query']!r})"
        )
