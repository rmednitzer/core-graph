"""api.mcp.tools.vector_search — Semantic similarity search via pgvector."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any

from prometheus_client import Histogram
from pydantic import BaseModel

from api.config import (
    DEFAULT_TLP,
    EMBEDDING_DIMENSIONS,
    EMBEDDING_MODEL,
    EMBEDDING_PROVIDER,
    EMBEDDING_URL,
)
from api.db import get_connection

logger = logging.getLogger(__name__)

vector_search_duration = Histogram(
    "cg_vector_search_duration_seconds",
    "Vector similarity search time",
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
)


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


# -- Circuit breaker state ---------------------------------------------------

_embedding_failures = 0
_CIRCUIT_OPEN_THRESHOLD = 5
_circuit_opened_at: float | None = None
_CIRCUIT_RESET_SECONDS = 60


def _check_circuit() -> bool:
    """Return True if the circuit is closed (requests allowed)."""
    global _embedding_failures, _circuit_opened_at
    if _embedding_failures < _CIRCUIT_OPEN_THRESHOLD:
        return True
    if _circuit_opened_at is None:
        return True
    elapsed = time.monotonic() - _circuit_opened_at
    if elapsed >= _CIRCUIT_RESET_SECONDS:
        # Half-open: allow one attempt
        return True
    return False


def _record_success() -> None:
    global _embedding_failures, _circuit_opened_at
    _embedding_failures = 0
    _circuit_opened_at = None


def _record_failure() -> None:
    global _embedding_failures, _circuit_opened_at
    _embedding_failures += 1
    if _embedding_failures >= _CIRCUIT_OPEN_THRESHOLD:
        _circuit_opened_at = time.monotonic()
        logger.warning(
            "Embedding circuit breaker opened after %d failures",
            _embedding_failures,
        )


# -- Embedding generation ----------------------------------------------------


async def generate_embedding(text: str) -> tuple[list[float], str]:
    """Generate an embedding vector from text.

    Uses the configured embedding provider (ollama or openai-compatible).
    Includes retry logic with exponential backoff and circuit breaker.

    Returns:
        Tuple of (embedding vector, model name).

    Raises:
        NotImplementedError: If provider is 'none'.
        RuntimeError: If circuit breaker is open.
    """
    if EMBEDDING_PROVIDER == "none":
        raise NotImplementedError("Embedding model not configured (CG_EMBEDDING_PROVIDER=none)")

    if not _check_circuit():
        raise RuntimeError("Embedding circuit breaker is open, skipping request")

    import httpx

    last_exc: Exception | None = None
    backoff_delays = [1, 2, 4]

    for attempt in range(3):
        try:
            vector = await _call_embedding_provider(httpx, text)
            _record_success()
            return (vector, EMBEDDING_MODEL)
        except Exception as exc:
            last_exc = exc
            logger.warning(
                "Embedding attempt %d/3 failed: %s",
                attempt + 1,
                exc,
            )
            if attempt < 2:
                await asyncio.sleep(backoff_delays[attempt])

    _record_failure()
    raise last_exc  # type: ignore[misc]


async def _call_embedding_provider(httpx: Any, text: str) -> list[float]:
    """Call the configured embedding provider and return the vector."""
    if EMBEDDING_PROVIDER == "ollama":
        url = f"{EMBEDDING_URL.rstrip('/')}/api/embed"
        payload = {"model": EMBEDDING_MODEL, "input": text}
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            body = resp.json()
            embeddings = body.get("embeddings", [])
            if not embeddings:
                raise ValueError("Ollama returned no embeddings")
            return embeddings[0][:EMBEDDING_DIMENSIONS]

    elif EMBEDDING_PROVIDER == "openai":
        url = f"{EMBEDDING_URL.rstrip('/')}/v1/embeddings"
        payload = {"model": EMBEDDING_MODEL, "input": text}
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            body = resp.json()
            data = body.get("data", [])
            if not data:
                raise ValueError("OpenAI-compatible API returned no embeddings")
            return data[0]["embedding"][:EMBEDDING_DIMENSIONS]

    else:
        raise ValueError(f"Unknown embedding provider: {EMBEDDING_PROVIDER}")


async def vector_search(
    text: str | None = None,
    limit: int = 10,
    *,
    vector: list[float] | None = None,
    caller_identity: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Search embeddings by cosine similarity.

    Accepts either a pre-computed vector or raw text. For raw text,
    calls generate_embedding() which requires an embedding provider.

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
        query_vector, _ = await generate_embedding(text)
    else:
        raise ValueError("Either 'text' or 'vector' must be provided")

    correlation_id = uuid.uuid4()
    caller = caller_identity or {"max_tlp": DEFAULT_TLP, "allowed_compartments": []}

    t_start = time.perf_counter()

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

        vector_search_duration.observe(time.perf_counter() - t_start)

        logger.info(
            "Vector search: correlation=%s results=%d",
            correlation_id,
            len(rows),
        )
        return [dict(r) for r in rows]
