"""api.mcp.tools.vector_search — Semantic similarity search via pgvector."""

from __future__ import annotations

import logging
from typing import Any

import psycopg
from psycopg.rows import dict_row
from pydantic import BaseModel

logger = logging.getLogger(__name__)

PG_DSN = "postgresql://cg_admin:cg_dev_only@localhost:5432/core_graph"


class VectorSearchInput(BaseModel):
    """Input model for vector_search tool."""

    text: str
    limit: int = 10


class VectorSearchResult(BaseModel):
    """Output model for a single search result."""

    graph_id: int
    label: str
    content: str | None
    distance: float


async def vector_search(text: str, limit: int = 10) -> list[dict[str, Any]]:
    """Search embeddings by cosine similarity.

    Args:
        text: Query text (or pre-computed vector in future).
        limit: Maximum number of results to return.

    Returns:
        List of matching entities ranked by distance.
    """
    # TODO: generate embedding from text using configured model
    # For now, accept a pre-computed vector or return empty results
    # placeholder_embedding = await generate_embedding(text)

    async with await psycopg.AsyncConnection.connect(PG_DSN, row_factory=dict_row) as conn:
        # Set RLS session variables
        await conn.execute("select set_config('app.max_tlp', '2', true)")

        # TODO: replace placeholder with actual embedding vector
        # The query below is the production pattern; it requires a real embedding
        #
        # cursor = await conn.execute(
        #     """
        #     select graph_id, label, content,
        #            embedding <=> %s::vector as distance
        #     from embeddings
        #     order by embedding <=> %s::vector
        #     limit %s
        #     """,
        #     (placeholder_embedding, placeholder_embedding, limit),
        # )
        # rows = await cursor.fetchall()
        # return [dict(r) for r in rows]

        logger.info("vector_search called with text=%r limit=%d", text[:50], limit)

        # TODO: implement embedding generation and search
        return []
