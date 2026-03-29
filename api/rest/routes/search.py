"""api.rest.routes.search — Vector search endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel

from api.mcp.tools.vector_search import vector_search

router = APIRouter()


class SearchRequest(BaseModel):
    text: str | None = None
    vector: list[float] | None = None
    limit: int = 10


@router.post("/search")
async def post_search(body: SearchRequest, request: Request) -> list[dict]:
    """Semantic similarity search over graph embeddings."""
    identity = getattr(request.state, "identity", None)
    if identity is not None:
        caller = {
            "max_tlp": identity.max_tlp,
            "actor": identity.sub,
            "allowed_compartments": identity.allowed_compartments,
        }
    else:
        from api.config import DEFAULT_TLP

        tlp = int(request.headers.get("X-CG-TLP", "0") or "0")
        caller = {
            "max_tlp": tlp or DEFAULT_TLP,
            "actor": "rest_api",
            "allowed_compartments": [],
        }
    return await vector_search(
        text=body.text,
        limit=body.limit,
        vector=body.vector,
        caller_identity=caller,
    )
