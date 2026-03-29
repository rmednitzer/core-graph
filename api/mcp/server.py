"""api.mcp.server — MCP server for core-graph.

Exposes five tools for AI agent interaction with the graph-vector
knowledge platform. Each tool enforces RLS via PostgreSQL session
variables and logs requests to the audit trail.
"""

from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from api.mcp.tools.cypher_query import cypher_query
from api.mcp.tools.entity_resolve import entity_resolve
from api.mcp.tools.ingest_event import ingest_event
from api.mcp.tools.stix_lookup import stix_lookup
from api.mcp.tools.vector_search import vector_search

logger = logging.getLogger(__name__)

mcp = FastMCP(
    "core-graph",
    description="Converged graph-vector knowledge platform for threat intelligence, "
    "security events, OSINT, compliance, AI memory, and forensic timelines.",
)


@mcp.tool()
async def tool_cypher_query(template: str, params: dict | None = None) -> list[dict]:
    """Execute a validated Cypher query against the core graph.

    Only named query templates are permitted. Pass the template name
    and parameters to bind. Results are filtered by TLP clearance via RLS.
    """
    return await cypher_query(template, params or {})


@mcp.tool()
async def tool_vector_search(text: str, limit: int = 10) -> list[dict]:
    """Search graph entities by semantic similarity.

    Generates an embedding for the input text and queries the pgvector
    HNSW index. Returns ranked results with graph_id, distance, and
    content preview.
    """
    return await vector_search(text=text, limit=limit)


@mcp.tool()
async def tool_entity_resolve(ioc_type: str, value: str) -> dict | None:
    """Look up a canonical entity by IOC type and value.

    Returns the vertex properties if the entity exists in the graph.
    """
    return await entity_resolve(ioc_type, value)


@mcp.tool()
async def tool_stix_lookup(stix_type: str, stix_id: str) -> dict | None:
    """Query a STIX 2.1 object stored as a graph vertex.

    Returns the STIX JSON representation of the object.
    """
    return await stix_lookup(stix_type, stix_id)


@mcp.tool()
async def tool_ingest_event(event: dict) -> dict:
    """Ingest an OCSF-normalised security event.

    Validates the event, publishes it to NATS JetStream for async
    processing, and returns an acknowledgement with the message
    sequence number.
    """
    return await ingest_event(event)


def main() -> None:
    """Run the MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
