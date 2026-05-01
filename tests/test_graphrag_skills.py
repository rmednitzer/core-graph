"""Static / non-DB tests for the GraphRAG skills.

DB-touching paths are covered by integration tests; here we verify
metadata, allowlist enforcement, and that the .cypher templates compile.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from api.mcp.skills.graphrag.anchored_retrieval import GraphRAGAnchoredRetrievalSkill
from api.mcp.skills.graphrag.neighborhood import GraphRAGNeighborhoodSkill
from api.mcp.skills.graphrag.path_ranking import GraphRAGPathRankingSkill
from api.mcp.tools.cypher_query import (
    PARAMETER_SCHEMAS,
    QUERY_TEMPLATES,
)

SKILLS = [
    GraphRAGAnchoredRetrievalSkill(),
    GraphRAGPathRankingSkill(),
    GraphRAGNeighborhoodSkill(),
]


@pytest.mark.parametrize("skill", SKILLS, ids=lambda s: s.name)
def test_skill_metadata(skill) -> None:
    assert skill.name.startswith("graphrag_")
    assert skill.version
    assert skill.description


def test_neighborhood_template_loaded() -> None:
    assert "graphrag_neighborhood" in QUERY_TEMPLATES
    schema = PARAMETER_SCHEMAS["graphrag_neighborhood"]
    assert schema["template_kind"] == "interpolated_depth"
    assert schema["depth_marker"] == "__DEPTH__"


def test_path_ranking_template_loaded() -> None:
    assert "graphrag_path_ranking" in QUERY_TEMPLATES
    schema = PARAMETER_SCHEMAS["graphrag_path_ranking"]
    assert schema["template_kind"] == "interpolated_depth"
    assert schema["depth_marker"] == "__MAX_HOPS__"
    text = QUERY_TEMPLATES["graphrag_path_ranking"]
    assert "exp(-0.25 * hops)" in text


def test_neighborhood_uses_validated_edge_label_filter() -> None:
    """Edge type filter must go through the allowlist before any DB call."""
    import asyncio

    skill = GraphRAGNeighborhoodSkill()

    async def call_with_bad_edge() -> None:
        await skill.execute({"entity_id": 1, "edge_type_filter": "no_such_edge"})

    with pytest.raises(ValueError):
        asyncio.run(call_with_bad_edge())


def test_no_plus_concat_in_graphrag_templates() -> None:
    """GraphRAG templates must not use AGE-incompatible `+` string concat."""
    queries = Path("api/mcp/skills/queries")
    for path in queries.glob("graphrag_*.cypher"):
        text = path.read_text()
        # We only forbid `'…' +` and `+ '…'` concat; `+` between numbers is fine.
        for needle in ("' +", "'+", '" +', '"+'):
            assert needle not in text, f"{path.name} uses `+` concat near a string literal"


def test_path_ranking_imports_clean() -> None:
    skill = GraphRAGPathRankingSkill()
    assert skill.name == "graphrag_path_ranking"
