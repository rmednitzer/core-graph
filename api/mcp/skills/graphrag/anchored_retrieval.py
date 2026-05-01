"""GraphRAG: anchored retrieval — hybrid search with N-hop expansion."""

from __future__ import annotations

from typing import Any

from api.mcp.skills.base import SkillBase, SkillResult
from api.mcp.tools.cypher_query import cypher_query
from api.mcp.tools.hybrid_search import hybrid_search


class GraphRAGAnchoredRetrievalSkill(SkillBase):
    name = "graphrag_anchored_retrieval"
    description = (
        "Hybrid (BM25 + vector) candidate retrieval, expanded by 2-hop "
        "AGE neighbourhood, scored by vector_score * 0.6 + graph_centrality "
        "* 0.2 + recency * 0.2."
    )
    version = "1.0.0"

    VECTOR_WEIGHT = 0.6
    CENTRALITY_WEIGHT = 0.2
    RECENCY_WEIGHT = 0.2

    async def execute(
        self,
        params: dict[str, Any],
        caller_identity: dict[str, Any] | None = None,
    ) -> SkillResult:
        query = self._require_param(params, "query")
        anchor_entity_id = params.get("anchor_entity_id")
        k = int(params.get("k", 10))
        depth = int(params.get("depth", 2))

        hits = await hybrid_search(
            query=query,
            k=max(k * 4, k),
            ef_search=int(params.get("ef_search", 100)),
            rerank=False,
            caller_identity=caller_identity,
        )

        candidates: list[dict[str, Any]] = []
        gaps: list[str] = []

        if anchor_entity_id is not None:
            # Constrain to the anchor's neighbourhood (e.g. CISO is asking
            # "what does the graph already say near this incident?").
            anchor_subgraph = await cypher_query(
                "graphrag_neighborhood",
                {"entity_id": int(anchor_entity_id), "depth": depth},
                caller_identity,
            )
            allowed_ids = {int(row["neighbour_id"]) for row in anchor_subgraph if row.get("neighbour_id") is not None}
            allowed_ids.add(int(anchor_entity_id))
            hits = [h for h in hits if h.graph_id in allowed_ids]
            if not hits:
                gaps.append("No hybrid hits intersect the anchor neighbourhood")

        if not hits:
            return SkillResult(
                skill_name=self.name,
                confidence=0.2,
                data=[],
                summary="anchored_retrieval returned no hits",
                gaps=gaps or ["No candidates from hybrid_search"],
                sources=["layer_5_memory", "layer_7_infrastructure"],
            )

        # Expand each candidate by `depth` hops to assemble subgraph + centrality.
        for hit in hits[:k]:
            subgraph = await cypher_query(
                "graphrag_neighborhood",
                {"entity_id": hit.graph_id, "depth": depth},
                caller_identity,
            )
            centrality = float(len({int(r["neighbour_id"]) for r in subgraph if r.get("neighbour_id") is not None}))
            recency = 1.0 / (1.0 + (hit.bm25_rank or 1))
            score = (
                self.VECTOR_WEIGHT * hit.score
                + self.CENTRALITY_WEIGHT * (centrality / max(centrality + 1.0, 1.0))
                + self.RECENCY_WEIGHT * recency
            )
            candidates.append(
                {
                    "graph_id": hit.graph_id,
                    "label": hit.label,
                    "content": hit.content,
                    "hybrid_score": hit.score,
                    "centrality": centrality,
                    "recency": recency,
                    "score": round(score, 6),
                    "subgraph_size": len(subgraph),
                }
            )

        candidates.sort(key=lambda c: c["score"], reverse=True)
        confidence = 0.5 + 0.05 * min(len(candidates), 10)

        return SkillResult(
            skill_name=self.name,
            confidence=round(min(confidence, 1.0), 2),
            data=candidates,
            summary=f"anchored_retrieval returned {len(candidates)} ranked candidates",
            gaps=gaps,
            sources=["layer_5_memory", "layer_7_infrastructure"],
        )
