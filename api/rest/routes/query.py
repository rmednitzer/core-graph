"""api.rest.routes.query — Cypher query execution endpoint."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from api.mcp.tools.cypher_query import cypher_query

router = APIRouter()


class QueryRequest(BaseModel):
    template: str
    params: dict[str, Any] = {}


@router.post("/query")
async def post_query(body: QueryRequest, request: Request) -> dict:
    """Execute a named Cypher query template."""
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
    try:
        rows = await cypher_query(body.template, body.params, caller_identity=caller)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"rows": rows, "count": len(rows)}
