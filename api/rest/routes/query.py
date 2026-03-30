"""api.rest.routes.query — Cypher query execution endpoint."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from api.mcp.tools.cypher_query import cypher_query
from api.rest.routes.helpers import caller_from_request

router = APIRouter()


class QueryRequest(BaseModel):
    template: str
    params: dict[str, Any] = {}


@router.post("/query")
async def post_query(body: QueryRequest, request: Request) -> dict:
    """Execute a named Cypher query template."""
    caller = caller_from_request(request)
    try:
        rows = await cypher_query(body.template, body.params, caller_identity=caller)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"rows": rows, "count": len(rows)}
