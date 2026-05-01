"""api.mcp.tools.vector_search — Semantic similarity search via pgvector."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any

from pydantic import BaseModel

from api.config import (
    DEFAULT_TLP,
    EMBEDDING_DIMENSIONS,
    EMBEDDING_MODEL,
    EMBEDDING_PROVIDER,
    EMBEDDING_URL,
    VALKEY_URL,
)
from api.db import get_connection
from api.utils.circuit_breaker import CircuitBreaker

logger = logging.getLogger(__name__)

try:
    from prometheus_client import Histogram

    vector_search_duration: Histogram | None = Histogram(
        "cg_vector_search_duration_seconds",
        "Vector similarity search time",
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
    )
except ImportError:
    vector_search_duration = None


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


# -- Distributed circuit breaker (Valkey-backed, local fallback) --------------

_breakers: dict[str, CircuitBreaker] = {}
_valkey_client: Any | None = None
_valkey_init_failed: bool = False


def _shared_valkey() -> Any | None:
    """Process-wide Valkey client, lazy-initialised once.

    Returning a single client (instead of creating one per model_id) avoids
    the connection / fd leak that arose in multi-model deployments where
    `_get_breaker` was called repeatedly with new model ids.
    """
    global _valkey_client, _valkey_init_failed
    if _valkey_client is not None or _valkey_init_failed:
        return _valkey_client
    try:
        import redis.asyncio as aioredis

        _valkey_client = aioredis.from_url(VALKEY_URL, decode_responses=True)
    except Exception:
        logger.warning(
            "Could not initialise Valkey client for circuit breaker; "
            "using local fallback for all models",
            exc_info=True,
        )
        _valkey_init_failed = True
    return _valkey_client


async def close_breaker_resources() -> None:
    """Close the shared Valkey client (call on app shutdown).

    Safe to call multiple times. Resets the singleton so the next caller
    can re-initialise it.
    """
    global _valkey_client, _valkey_init_failed
    if _valkey_client is not None:
        try:
            await _valkey_client.aclose()
        except Exception:
            logger.debug("Error closing shared Valkey client", exc_info=True)
        _valkey_client = None
    _valkey_init_failed = False
    _breakers.clear()


async def _get_breaker(model_id: str) -> CircuitBreaker:
    """Return the per-model CircuitBreaker, sharing one Valkey client."""
    if model_id in _breakers:
        return _breakers[model_id]
    breaker = CircuitBreaker(
        key=f"cg:cb:embedding:{model_id}",
        threshold=5,
        window_seconds=60,
        reset_seconds=60,
        valkey=_shared_valkey(),
    )
    _breakers[model_id] = breaker
    return breaker


# -- Embedding generation ----------------------------------------------------


async def generate_embedding(text: str) -> tuple[list[float], str]:
    """Generate an embedding vector from text.

    Uses the configured embedding provider (ollama or openai-compatible).
    Includes retry logic with exponential backoff and a Valkey-backed
    circuit breaker keyed on the model id.
    """
    if EMBEDDING_PROVIDER == "none":
        raise NotImplementedError("Embedding model not configured (CG_EMBEDDING_PROVIDER=none)")

    breaker = await _get_breaker(EMBEDDING_MODEL)
    if not await breaker.allow():
        raise RuntimeError(f"Embedding circuit breaker open for model {EMBEDDING_MODEL!r}")

    import httpx

    last_exc: Exception | None = None
    backoff_delays = [1, 2, 4]

    for attempt in range(3):
        try:
            vector = await _call_embedding_provider(httpx, text)
            await breaker.record_success()
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

    await breaker.record_failure()
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
    model_id: str | None = None,
    ef_search: int = 100,
    use_halfvec: bool = False,
) -> list[dict[str, Any]]:
    """Search embeddings by cosine similarity.

    Accepts either a pre-computed vector or raw text. For raw text, calls
    generate_embedding() which requires an embedding provider. Set
    `use_halfvec=True` to query the half-precision index for lower latency
    at a small recall cost.

    Args:
        text: Query text (requires embedding model to be configured).
        limit: Maximum number of results to return.
        vector: Pre-computed embedding vector (list of floats).
        caller_identity: MCP session context for RLS enforcement.
        model_id: Restrict to embeddings produced by this model.
        ef_search: HNSW dynamic candidate list (1..1000); higher = better recall,
            slower latency. Set transaction-locally via SET LOCAL hnsw.ef_search.
        use_halfvec: Query the halfvec column instead of full precision.
    """
    if vector is not None:
        query_vector = vector
    elif text is not None:
        query_vector, _ = await generate_embedding(text)
    else:
        raise ValueError("Either 'text' or 'vector' must be provided")

    correlation_id = uuid.uuid4()
    caller = caller_identity or {"max_tlp": DEFAULT_TLP, "allowed_compartments": []}

    column = "embedding_half" if use_halfvec else "embedding"
    cast = "halfvec" if use_halfvec else "vector"

    where_clause = ""
    extra_params: list[Any] = []
    if model_id is not None:
        where_clause = "where model_id = %s"
        extra_params.append(model_id)

    sql = (
        f"select graph_id, label, content, "
        f"       {column} <=> %s::{cast} as distance "
        f"from embeddings "
        f"{where_clause} "
        f"order by {column} <=> %s::{cast} "
        f"limit %s"
    )
    qv = str(query_vector)

    t_start = time.perf_counter()

    async with get_connection(caller) as conn:
        await conn.execute(
            "select set_config('hnsw.ef_search', %s, true)",
            (str(int(ef_search)),),
        )
        cursor = await conn.execute(sql, (qv, *extra_params, qv, limit))
        rows = await cursor.fetchall()

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

        if vector_search_duration is not None:
            vector_search_duration.observe(time.perf_counter() - t_start)

        logger.info(
            "Vector search: correlation=%s results=%d model=%s halfvec=%s ef=%d",
            correlation_id,
            len(rows),
            model_id or "*",
            use_halfvec,
            ef_search,
        )
        return [dict(r) for r in rows]
