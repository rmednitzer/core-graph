"""ingest.graph_writer — Graph upsert worker.

Consumes enriched entities from NATS JetStream and merges them into the
AGE graph using parameterised prepared statements.

Security: All Cypher queries use ag_catalog.cypher() with parameter binding.
Never constructs Cypher strings via concatenation (CVE-2022-45786 mitigation).
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import nats
import psycopg
from nats.js.api import ConsumerConfig, StreamConfig
from psycopg.rows import dict_row

logger = logging.getLogger(__name__)

# -- Cypher merge templates (parameterised, never concatenated) ----------------

MERGE_TEMPLATES: dict[str, str] = {
    "CanonicalIP": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:CanonicalIP {value: $value})
            on create set v.first_seen = $now, v.tlp_level = $tlp
            on match set v.last_seen = $now
            return id(v)
        $$, $1) as (id agtype)
    """,
    "CanonicalDomain": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:CanonicalDomain {value: $value})
            on create set v.first_seen = $now, v.tlp_level = $tlp
            on match set v.last_seen = $now
            return id(v)
        $$, $1) as (id agtype)
    """,
    "Indicator": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Indicator {value: $value, indicator_type: $indicator_type})
            on create set v.first_seen = $now, v.tlp_level = $tlp
            on match set v.last_seen = $now
            return id(v)
        $$, $1) as (id agtype)
    """,
    "SecurityEvent": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:SecurityEvent {event_id: $event_id})
            on create set v.time = $now, v.category = $category,
                          v.severity = $severity, v.tlp_level = $tlp
            return id(v)
        $$, $1) as (id agtype)
    """,
}


async def _ensure_stream(js: nats.js.JetStreamContext) -> None:
    """Ensure the enriched entity stream exists."""
    await js.add_stream(
        StreamConfig(
            name="ENRICHED",
            subjects=["enriched.entity.>"],
            retention="work_queue",
            max_bytes=1_073_741_824,
        )
    )


async def _write_audit_entry(
    conn: psycopg.AsyncConnection[Any],
    entity_id: int | None,
    entity_label: str,
    operation: str,
    new_value_hash: str | None,
    actor: str,
    correlation_id: uuid.UUID | None = None,
) -> None:
    """Insert an entry into the append-only audit log."""
    await conn.execute(
        """
        insert into audit_log (entity_id, entity_label, operation,
                               new_value_hash, actor, correlation_id)
        values (%s, %s, %s, %s, %s, %s)
        """,
        (entity_id, entity_label, operation, new_value_hash, actor, correlation_id),
    )


async def _merge_entity(
    conn: psycopg.AsyncConnection[Any],
    label: str,
    params: dict[str, Any],
) -> int | None:
    """Execute a parameterised Cypher MERGE and return the vertex id."""
    template = MERGE_TEMPLATES.get(label)
    if template is None:
        logger.warning("No merge template for label %s", label)
        return None

    # AGE expects parameters as a JSON-encoded agtype argument
    agtype_param = json.dumps(params)
    row = await conn.execute(template, (agtype_param,))
    result = await row.fetchone()
    if result:
        return int(str(result["id"]).strip('"'))
    return None


async def _process_message(
    conn: psycopg.AsyncConnection[Any],
    msg: Any,
) -> None:
    """Process a single enriched entity message."""
    try:
        payload = json.loads(msg.data.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.error("Invalid message payload, skipping")
        await msg.ack()
        return

    label = payload.get("label", "")
    params = payload.get("properties", {})
    params["now"] = datetime.now(UTC).isoformat()
    params.setdefault("tlp", 1)

    correlation_id = uuid.uuid4()

    # Set RLS session variables
    await conn.execute("select set_config('app.max_tlp', '4', true)")

    vertex_id = await _merge_entity(conn, label, params)

    # Write temporal fact if applicable
    if vertex_id and payload.get("temporal"):
        temporal = payload["temporal"]
        await conn.execute(
            """
            insert into temporal_facts
                (edge_id, edge_label, source_id, target_id,
                 fact_type, fact_value, t_valid, source, confidence)
            values (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                temporal.get("edge_id", 0),
                temporal.get("edge_label", "unknown"),
                temporal.get("source_id", 0),
                temporal.get("target_id", 0),
                temporal.get("fact_type", "observation"),
                json.dumps(temporal.get("fact_value", {})),
                datetime.now(UTC),
                temporal.get("source", "graph_writer"),
                temporal.get("confidence", 0.5),
            ),
        )

    await _write_audit_entry(
        conn,
        entity_id=vertex_id,
        entity_label=label,
        operation="MERGE",
        new_value_hash=None,  # TODO: compute hash of entity properties
        actor="graph_writer",
        correlation_id=correlation_id,
    )

    await conn.commit()
    await msg.ack()
    logger.info("Merged %s vertex_id=%s correlation=%s", label, vertex_id, correlation_id)


async def run(
    pg_dsn: str = "postgresql://cg_admin:cg_dev_only@localhost:5432/core_graph",
    nats_url: str = "nats://localhost:4222",
) -> None:
    """Main loop: consume from NATS and write to the graph."""
    nc = await nats.connect(nats_url)
    js = nc.jetstream()
    await _ensure_stream(js)

    conn = await psycopg.AsyncConnection.connect(pg_dsn, row_factory=dict_row)
    await conn.set_autocommit(False)

    # Set AGE search path
    await conn.execute("set search_path = ag_catalog, '$user', public")

    sub = await js.subscribe(
        "enriched.entity.>",
        durable="graph_writer",
        config=ConsumerConfig(ack_wait=30),
    )

    logger.info("Graph writer started, consuming enriched.entity.>")

    try:
        async for msg in sub.messages:
            try:
                await _process_message(conn, msg)
            except Exception:
                logger.exception("Error processing message")
                await conn.rollback()
                await msg.nak()
    finally:
        await conn.close()
        await nc.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(run())
