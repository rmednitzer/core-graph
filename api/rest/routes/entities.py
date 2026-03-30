"""api.rest.routes.entities — Entity and STIX lookup endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from api.mcp.tools.entity_resolve import entity_resolve
from api.mcp.tools.stix_lookup import stix_lookup
from api.rest.routes.helpers import caller_from_request

router = APIRouter()


@router.get("/entities/{ioc_type}/{value}")
async def get_entity(ioc_type: str, value: str, request: Request) -> dict:
    """Resolve a canonical entity by IOC type and value."""
    caller = caller_from_request(request)
    try:
        result = await entity_resolve(ioc_type, value, caller_identity=caller)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    return result


@router.get("/stix/{stix_type}/{stix_id:path}")
async def get_stix(stix_type: str, stix_id: str, request: Request) -> dict:
    """Look up a STIX 2.1 object by type and ID."""
    caller = caller_from_request(request)
    try:
        result = await stix_lookup(stix_type, stix_id, caller_identity=caller)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if result is None:
        raise HTTPException(status_code=404, detail="STIX object not found")
    return result
