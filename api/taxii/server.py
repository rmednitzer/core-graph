"""api.taxii.server — TAXII 2.1 federation server.

Implements core TAXII 2.1 endpoints per the OASIS TAXII 2.1 CS02
specification. Mounted under /taxii2/ in the FastAPI application.

All endpoints enforce OIDC auth via the existing middleware stack.
RLS enforcement flows through the shared connection pool.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

import nats
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from api.config import NATS_URL
from api.db import get_connection
from api.taxii.collections import COLLECTIONS
from api.taxii.models import (
    APIRootResponse,
    CollectionResource,
    CollectionsResponse,
    DiscoveryResponse,
    StatusResource,
    STIXBundle,
)

logger = logging.getLogger(__name__)

TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"
STIX_CONTENT_TYPE = "application/stix+json;version=2.1"
DEFAULT_PAGE_SIZE = 100

taxii_router = APIRouter()


def _caller_from_request(request: Request) -> dict[str, Any]:
    """Extract caller identity from request state."""
    identity = getattr(request.state, "identity", None)
    if identity is not None:
        return {
            "max_tlp": identity.max_tlp,
            "actor": identity.sub,
            "allowed_compartments": identity.allowed_compartments,
        }
    from api.config import DEFAULT_TLP

    return {
        "max_tlp": DEFAULT_TLP,
        "actor": "taxii_anonymous",
        "allowed_compartments": [],
    }


async def _write_audit(
    conn: Any,
    operation: str,
    actor: str,
    detail: str,
) -> None:
    """Write a TAXII operation audit log entry."""
    await conn.execute(
        """
        insert into audit_log (entity_id, entity_label, operation,
                               new_value_hash, actor, correlation_id)
        values (%s, %s, %s, %s, %s, %s)
        """,
        (None, "taxii", operation, None, actor, uuid.uuid4()),
    )


def _taxii_response(content: Any, status_code: int = 200) -> JSONResponse:
    """Build a TAXII JSON response with correct content type."""
    return JSONResponse(
        content=content,
        status_code=status_code,
        media_type=TAXII_CONTENT_TYPE,
    )


def _stix_response(
    content: Any,
    status_code: int = 200,
    date_added_first: str | None = None,
    date_added_last: str | None = None,
) -> JSONResponse:
    """Build a STIX JSON response with pagination headers."""
    headers: dict[str, str] = {}
    if date_added_first:
        headers["X-TAXII-Date-Added-First"] = date_added_first
    if date_added_last:
        headers["X-TAXII-Date-Added-Last"] = date_added_last
    return JSONResponse(
        content=content,
        status_code=status_code,
        media_type=STIX_CONTENT_TYPE,
        headers=headers if headers else None,
    )


# -- Discovery ------------------------------------------------------------------


@taxii_router.get("/")
async def discovery(request: Request) -> JSONResponse:
    """TAXII 2.1 Discovery endpoint (Section 4.1)."""
    caller = _caller_from_request(request)

    async with get_connection(caller) as conn:
        await _write_audit(conn, "TAXII_DISCOVERY", caller["actor"], "discovery")
        await conn.commit()

    base_url = str(request.base_url).rstrip("/")
    resp = DiscoveryResponse(
        title="core-graph TAXII 2.1 Server",
        description="Federated threat intelligence sharing via TAXII 2.1",
        default=f"{base_url}/taxii2/default/",
        api_roots=[f"{base_url}/taxii2/default/"],
    )
    return _taxii_response(resp.model_dump())


# -- API Root -------------------------------------------------------------------


@taxii_router.get("/{api_root}/")
async def api_root(api_root: str, request: Request) -> JSONResponse:
    """TAXII 2.1 API Root endpoint (Section 4.2)."""
    if api_root != "default":
        raise HTTPException(status_code=404, detail="Unknown API root")

    resp = APIRootResponse(
        title="core-graph Default API Root",
        description="Primary API root for core-graph STIX data",
        versions=["application/taxii+json;version=2.1"],
    )
    return _taxii_response(resp.model_dump())


# -- Collections ----------------------------------------------------------------


@taxii_router.get("/{api_root}/collections/")
async def list_collections(api_root: str, request: Request) -> JSONResponse:
    """TAXII 2.1 Collections endpoint (Section 5.1)."""
    if api_root != "default":
        raise HTTPException(status_code=404, detail="Unknown API root")

    collections = [
        CollectionResource(
            id=coll.id,
            title=coll.title,
            description=coll.description,
        )
        for coll in COLLECTIONS.values()
    ]
    resp = CollectionsResponse(collections=collections)
    return _taxii_response(resp.model_dump())


@taxii_router.get("/{api_root}/collections/{collection_id}/")
async def get_collection(api_root: str, collection_id: str, request: Request) -> JSONResponse:
    """TAXII 2.1 single Collection endpoint (Section 5.2)."""
    if api_root != "default":
        raise HTTPException(status_code=404, detail="Unknown API root")

    coll = COLLECTIONS.get(collection_id)
    if coll is None:
        raise HTTPException(status_code=404, detail="Unknown collection")

    resource = CollectionResource(
        id=coll.id,
        title=coll.title,
        description=coll.description,
    )
    return _taxii_response(resource.model_dump())


# -- Objects --------------------------------------------------------------------


@taxii_router.get("/{api_root}/collections/{collection_id}/objects/")
async def get_objects(
    api_root: str,
    collection_id: str,
    request: Request,
    added_after: str | None = Query(default=None),
    next: str | None = Query(default=None, alias="next"),
    match_type: str | None = Query(default=None, alias="match[type]"),
    match_id: str | None = Query(default=None, alias="match[id]"),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, le=1000),
) -> JSONResponse:
    """TAXII 2.1 Get Objects endpoint (Section 5.3)."""
    if api_root != "default":
        raise HTTPException(status_code=404, detail="Unknown API root")

    coll = COLLECTIONS.get(collection_id)
    if coll is None:
        raise HTTPException(status_code=404, detail="Unknown collection")

    caller = _caller_from_request(request)
    offset = int(next) if next and next.isdigit() else 0
    after_ts = added_after or "1970-01-01T00:00:00Z"

    objects: list[dict] = []

    async with get_connection(caller) as conn:
        await _write_audit(conn, "TAXII_GET_OBJECTS", caller["actor"], collection_id)

        for label in coll.graph_label_filter:
            query = f"""
                select * from ag_catalog.cypher('core_graph', $$
                    match (v:{label})
                    return properties(v)
                $$) as (props agtype)
            """
            result = await conn.execute(query)
            rows = await result.fetchall()
            for row in rows:
                props = row["props"]
                if isinstance(props, str):
                    props = json.loads(props)

                # Apply added_after filter
                t_recorded = props.get("t_recorded", props.get("first_seen", ""))
                if t_recorded and t_recorded <= after_ts:
                    continue

                # Apply match[type] filter
                stix_type = props.get("stix_type", "")
                if match_type and stix_type != match_type:
                    continue

                # Apply match[id] filter
                stix_id = props.get("stix_id", props.get("id", ""))
                if match_id and stix_id != match_id:
                    continue

                objects.append(props)

        await conn.commit()

    # Pagination
    total = len(objects)
    page = objects[offset : offset + limit]
    next_offset = offset + limit if offset + limit < total else None

    date_first = None
    date_last = None
    if page:
        timestamps = [o.get("t_recorded", o.get("first_seen", "")) for o in page]
        timestamps = [t for t in timestamps if t]
        if timestamps:
            date_first = min(timestamps)
            date_last = max(timestamps)

    bundle = STIXBundle(
        type="bundle",
        id=f"bundle--{uuid.uuid4()}",
        objects=page,
    )

    resp_content = bundle.model_dump()
    if next_offset is not None:
        resp_content["more"] = True
        resp_content["next"] = str(next_offset)

    return _stix_response(
        resp_content,
        date_added_first=date_first,
        date_added_last=date_last,
    )


@taxii_router.get("/{api_root}/collections/{collection_id}/objects/{object_id}/")
async def get_object_by_id(
    api_root: str,
    collection_id: str,
    object_id: str,
    request: Request,
) -> JSONResponse:
    """TAXII 2.1 Get Object by ID endpoint (Section 5.5)."""
    if api_root != "default":
        raise HTTPException(status_code=404, detail="Unknown API root")

    coll = COLLECTIONS.get(collection_id)
    if coll is None:
        raise HTTPException(status_code=404, detail="Unknown collection")

    caller = _caller_from_request(request)
    found: dict | None = None

    async with get_connection(caller) as conn:
        await _write_audit(
            conn, "TAXII_GET_OBJECT", caller["actor"], f"{collection_id}/{object_id}"
        )

        for label in coll.graph_label_filter:
            query = f"""
                select * from ag_catalog.cypher('core_graph', $$
                    match (v:{label})
                    return properties(v)
                $$) as (props agtype)
            """
            result = await conn.execute(query)
            rows = await result.fetchall()
            for row in rows:
                props = row["props"]
                if isinstance(props, str):
                    props = json.loads(props)
                stix_id = props.get("stix_id", props.get("id", ""))
                if stix_id == object_id:
                    found = props
                    break
            if found:
                break

        await conn.commit()

    if found is None:
        raise HTTPException(status_code=404, detail="Object not found")

    bundle = STIXBundle(
        type="bundle",
        id=f"bundle--{uuid.uuid4()}",
        objects=[found],
    )
    return _stix_response(bundle.model_dump())


# -- Add Objects ----------------------------------------------------------------


@taxii_router.post("/{api_root}/collections/{collection_id}/objects/")
async def add_objects(
    api_root: str,
    collection_id: str,
    request: Request,
) -> JSONResponse:
    """TAXII 2.1 Add Objects endpoint (Section 5.4).

    Accepts a STIX 2.1 bundle and publishes objects to NATS for ingestion.
    """
    if api_root != "default":
        raise HTTPException(status_code=404, detail="Unknown API root")

    coll = COLLECTIONS.get(collection_id)
    if coll is None:
        raise HTTPException(status_code=404, detail="Unknown collection")

    caller = _caller_from_request(request)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid JSON body")

    # Validate STIX bundle structure
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="Request body must be a JSON object")

    if body.get("type") != "bundle":
        raise HTTPException(
            status_code=422,
            detail="Request body must be a STIX 2.1 bundle (type='bundle')",
        )

    stix_objects = body.get("objects", [])
    if not isinstance(stix_objects, list):
        raise HTTPException(status_code=422, detail="Bundle objects must be a list")

    status_id = str(uuid.uuid4())
    success_count = 0
    failure_count = 0

    async with get_connection(caller) as conn:
        await _write_audit(conn, "TAXII_ADD_OBJECTS", caller["actor"], collection_id)
        await conn.commit()

    # Publish each object to NATS for ingestion
    try:
        nc = await nats.connect(NATS_URL)
        js = nc.jetstream()

        for obj in stix_objects:
            try:
                if not isinstance(obj, dict) or "type" not in obj:
                    failure_count += 1
                    continue
                payload = json.dumps(obj, default=str).encode()
                await js.publish(
                    f"ingest.taxii.{collection_id}",
                    payload,
                )
                success_count += 1
            except Exception:
                logger.exception("Failed to publish STIX object to NATS")
                failure_count += 1

        await nc.close()
    except Exception:
        logger.exception("Failed to connect to NATS for TAXII ingest")
        failure_count = len(stix_objects)
        success_count = 0

    status = StatusResource(
        id=status_id,
        status="complete",
        total_count=len(stix_objects),
        success_count=success_count,
        failure_count=failure_count,
        pending_count=0,
    )
    return _taxii_response(status.model_dump(), status_code=202)
