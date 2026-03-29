"""api.mcp.tools.vector_search — Semantic similarity search via pgvector."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from pydantic import BaseModel

from api.config import DEFAULT_TLP
from api.db import get_connection

logger = logging.getLogger(__name__)


class VectorSearchInput(BaseModel):
    """Input model for vector_search tool."""

    text: str | None = None
    vector: list[float] | None = None
    limit: int = 10


class VectorSearchResult(BaseModel):
    """Output model for a single search result."""

    graph_id: int
    label: str
    content: str | None
    distance: float


async def generate_embedding(text: str) -> list[float]:
    """Generate an embedding vector from text.

    Raises NotImplementedError until an embedding model is configured.
    """
    raise NotImplementedError("Embedding model not configured")


async def vector_search(
    text: str | None = None,
    limit: int = 10,
    *,
    vector: list[float] | None = None,
    caller_identity: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Search embeddings by cosine similarity.

    Accepts either a pre-computed vector or raw text. For raw text,
    calls generate_embedding() which currently raises NotImplementedError.

    Args:
        text: Query text (requires embedding model to be configured).
        limit: Maximum number of results to return.
        vector: Pre-computed embedding vector (list of floats).
        caller_identity: MCP session context for RLS enforcement.

    Returns:
        List of matching entities ranked by distance.
    """
    # Determine the query vector
    if vector is not None:
        query_vector = vector
    elif text is not None:
        query_vector = await generate_embedding(text)
    else:
        raise ValueError("Either 'text' or 'vector' must be provided")

    correlation_id = uuid.uuid4()
    caller = caller_identity or {"max_tlp": DEFAULT_TLP, "allowed_compartments": []}

    async with get_connection(caller) as conn:
        cursor = await conn.execute(
            """
            select graph_id, label, content,
                   embedding <=> %s::vector as distance
            from embeddings
            order by embedding <=> %s::vector
            limit %s
            """,
            (str(query_vector), str(query_vector), limit),
        )
        rows = await cursor.fetchall()

        # Write audit log entry
        await conn.execute(
            """
            insert into audit_log
                (entity_label, operation, actor, correlation_id)
            values (%s, %s, %s, %s)
            """,
            (
                "vector_search",
                "SEARCH",
                caller_identity.get("actor", "mcp") if caller_identity else "mcp",
                correlation_id,
            ),
        )
        await conn.commit()

        logger.info(
            "Vector search: correlation=%s results=%d",
            correlation_id,
            len(rows),
        )
        return [dict(r) for r in rows]
