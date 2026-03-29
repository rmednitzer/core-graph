"""api.rest.routes.events — Event ingestion endpoint."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

from api.mcp.tools.ingest_event import ingest_event

router = APIRouter()


@router.post("/events")
async def post_event(body: dict[str, Any], request: Request) -> dict:
    """Ingest an OCSF-normalised security event via NATS JetStream."""
    identity = getattr(request.state, "identity", None)
    caller = {
        "actor": identity.sub if identity is not None else "rest_api",
    }
    result = await ingest_event(body, caller_identity=caller)
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result.get("errors", []))
    return result
