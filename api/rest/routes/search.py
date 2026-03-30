"""api.rest.routes.search — Vector search endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel

from api.mcp.tools.vector_search import vector_search
from api.rest.routes.helpers import caller_from_request

router = APIRouter()


class SearchRequest(BaseModel):
    text: str | None = None
    vector: list[float] | None = None
    limit: int = 10


@router.post("/search")
async def post_search(body: SearchRequest, request: Request) -> list[dict]:
    """Semantic similarity search over graph embeddings."""
    caller = caller_from_request(request)
    return await vector_search(
        text=body.text,
        limit=body.limit,
        vector=body.vector,
        caller_identity=caller,
    )
