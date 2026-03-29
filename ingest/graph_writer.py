"""ingest.graph_writer — Graph upsert worker.

Consumes enriched entities from NATS JetStream and merges them into the
AGE graph using parameterised prepared statements.

Security: All Cypher queries use ag_catalog.cypher() with parameter binding.
Never constructs Cypher strings via concatenation (CVE-2022-45786 mitigation).
"""

from __future__ import annotations

import asyncio
import hashlib
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
    # -- Layer 7: Infrastructure & Assets ------------------------------------
    "Host": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Host {canonical_key: $canonical_key})
            on create set v.name = $name, v.host_type = $host_type,
                          v.platform = $platform, v.status = $status,
                          v.site = $site, v.tlp_level = $tlp,
                          v.primary_ip = $primary_ip, v.netbox_id = $netbox_id,
                          v.first_seen = $now
            on match set v.last_seen = $now, v.status = $status,
                         v.platform = $platform,
                         v.primary_ip = $primary_ip, v.netbox_id = $netbox_id
            return id(v)
        $$, $1) as (id agtype)
    """,
    "Network": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Network {prefix: $prefix})
            on create set v.vlan_id = $vlan_id, v.site = $site,
                          v.description = $description, v.tlp_level = $tlp,
                          v.first_seen = $now
            on match set v.last_seen = $now
            return id(v)
        $$, $1) as (id agtype)
    """,
    "Site": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Site {name: $name})
            on create set v.slug = $slug, v.region = $region,
                          v.tlp_level = $tlp, v.first_seen = $now
            on match set v.last_seen = $now
            return id(v)
        $$, $1) as (id agtype)
    """,
    "Interface": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Interface {canonical_key: $canonical_key})
            on create set v.name = $name, v.mac_address = $mac_address,
                          v.enabled = $enabled, v.tlp_level = $tlp,
                          v.first_seen = $now
            on match set v.last_seen = $now, v.enabled = $enabled
            return id(v)
        $$, $1) as (id agtype)
    """,
    "Service": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Service {canonical_key: $canonical_key})
            on create set v.name = $name, v.protocol = $protocol,
                          v.ports = $ports, v.tlp_level = $tlp,
                          v.first_seen = $now
            on match set v.last_seen = $now
            return id(v)
        $$, $1) as (id agtype)
    """,
    "MonitoringAlert": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:MonitoringAlert {fingerprint: $fingerprint})
            on create set v.alertname = $alertname, v.severity = $severity,
                          v.status = $status, v.instance = $instance,
                          v.tlp_level = $tlp, v.starts_at = $starts_at,
                          v.ends_at = $ends_at, v.first_seen = $now
            on match set v.status = $status, v.ends_at = $ends_at,
                         v.last_seen = $now
            return id(v)
        $$, $1) as (id agtype)
    """,
    # -- Layer 8: IAM --------------------------------------------------------
    "Principal": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Principal {canonical_key: $canonical_key})
            on create set v.principal_id = $principal_id, v.username = $username,
                          v.email = $email, v.enabled = $enabled,
                          v.created_at = $created_at, v.last_login = $last_login,
                          v.source = $source, v.tlp_level = $tlp,
                          v.first_seen = $now
            on match set v.last_login = $last_login, v.enabled = $enabled,
                         v.last_seen = $now
            return id(v)
        $$, $1) as (id agtype)
    """,
    "Group": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Group {canonical_key: $canonical_key})
            on create set v.group_id = $group_id, v.name = $name,
                          v.path = $path, v.source = $source,
                          v.tlp_level = $tlp, v.first_seen = $now
            on match set v.last_seen = $now
            return id(v)
        $$, $1) as (id agtype)
    """,
    "Role": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Role {canonical_key: $canonical_key})
            on create set v.role_name = $role_name, v.realm = $realm,
                          v.client_id = $client_id, v.source = $source,
                          v.tlp_level = $tlp, v.first_seen = $now
            on match set v.last_seen = $now
            return id(v)
        $$, $1) as (id agtype)
    """,
    "Permission": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Permission {canonical_key: $canonical_key})
            on create set v.name = $name, v.resource = $resource,
                          v.source = $source, v.tlp_level = $tlp,
                          v.first_seen = $now
            on match set v.last_seen = $now
            return id(v)
        $$, $1) as (id agtype)
    """,
    "AccessPolicy": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:AccessPolicy {canonical_key: $canonical_key})
            on create set v.name = $name, v.source = $source,
                          v.tlp_level = $tlp, v.first_seen = $now
            on match set v.last_seen = $now
            return id(v)
        $$, $1) as (id agtype)
    """,
}

# -- Relationship merge templates (parameterised, never concatenated) --------

RELATIONSHIP_TEMPLATES: dict[str, str] = {
    "has_role": """
        select * from ag_catalog.cypher('core_graph', $$
            match (p:Principal {canonical_key: $principal_key})
            match (r:Role {canonical_key: $role_key})
            merge (p)-[:has_role {source: $source, t_recorded: $now}]->(r)
            return id(p)
        $$, $1) as (id agtype)
    """,
    "member_of": """
        select * from ag_catalog.cypher('core_graph', $$
            match (a {canonical_key: $principal_key})
            match (b {canonical_key: $group_key})
            merge (a)-[:member_of {source: $source, t_recorded: $now}]->(b)
            return id(a)
        $$, $1) as (id agtype)
    """,
    "grants": """
        select * from ag_catalog.cypher('core_graph', $$
            match (r:Role {canonical_key: $role_key})
            match (p:Permission {canonical_key: $permission_key})
            merge (r)-[:grants {source: $source, t_recorded: $now}]->(p)
            return id(r)
        $$, $1) as (id agtype)
    """,
    "actor_in": """
        select * from ag_catalog.cypher('core_graph', $$
            match (p:Principal {canonical_key: $principal_key})
            match (se:SecurityEvent {event_id: $event_id})
            merge (p)-[:actor_in {source: $source, t_recorded: $now}]->(se)
            return id(p)
        $$, $1) as (id agtype)
    """,
    "manages": """
        select * from ag_catalog.cypher('core_graph', $$
            match (mgr:Principal {canonical_key: $manager_key})
            match (sub:Principal {canonical_key: $subordinate_key})
            merge (mgr)-[:manages {source: $source, t_recorded: $now}]->(sub)
            return id(mgr)
        $$, $1) as (id agtype)
    """,
    "owns": """
        select * from ag_catalog.cypher('core_graph', $$
            match (p:Principal {canonical_key: $principal_key})
            match (a {canonical_key: $asset_key})
            merge (p)-[:owns {source: $source, t_recorded: $now}]->(a)
            return id(p)
        $$, $1) as (id agtype)
    """,
}


def _hash_properties(params: dict) -> str:
    """Compute SHA-256 of canonicalized entity properties for audit."""
    canonical = json.dumps(params, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


async def _ensure_stream(js: nats.js.JetStreamContext) -> None:
    """Ensure the enriched entity and relationship streams exist."""
    await js.add_stream(
        StreamConfig(
            name="ENRICHED",
            subjects=["enriched.entity.>", "enriched.relationship.>"],
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


async def _merge_relationship(
    conn: psycopg.AsyncConnection[Any],
    rel_type: str,
    params: dict[str, Any],
) -> int | None:
    """Execute a parameterised Cypher MERGE for an edge and return a vertex id."""
    template = RELATIONSHIP_TEMPLATES.get(rel_type)
    if template is None:
        logger.warning("No relationship template for type %s", rel_type)
        return None

    params["now"] = datetime.now(UTC).isoformat()
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
    """Process a single enriched entity or relationship message."""
    try:
        payload = json.loads(msg.data.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.error("Invalid message payload, skipping")
        await msg.ack()
        return

    # Set RLS session variables
    await conn.execute("select set_config('app.max_tlp', '4', true)")

    correlation_id = uuid.uuid4()

    # Route by subject prefix
    is_relationship = msg.subject.startswith("enriched.relationship.")

    if is_relationship:
        rel_type = payload.get("type", "")
        params = {k: v for k, v in payload.items() if k != "type"}
        vertex_id = await _merge_relationship(conn, rel_type, params)
        label = f"rel:{rel_type}"
    else:
        label = payload.get("label", "")
        params = payload.get("properties", {})
        params["now"] = datetime.now(UTC).isoformat()

        # IAM entities enforce TLP:AMBER floor at the application layer.
        # This is defense-in-depth alongside the RESTRICTIVE RLS policy in 010.
        _IAM_LABELS = {"Principal", "Group", "Role", "Permission", "AccessPolicy"}
        if label in _IAM_LABELS:
            params["tlp"] = max(params.get("tlp", 2), 2)
        else:
            params.setdefault("tlp", 1)

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
        new_value_hash=_hash_properties(params),
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
        "enriched.>",
        durable="graph_writer",
        config=ConsumerConfig(ack_wait=30),
    )

    logger.info("Graph writer started, consuming enriched.entity.> and enriched.relationship.>")

    # Ensure DLQ stream exists
    await js.add_stream(
        StreamConfig(
            name="DLQ",
            subjects=["dlq.>"],
            retention="work_queue",
            max_bytes=1_073_741_824,
        )
    )

    try:
        async for msg in sub.messages:
            try:
                await _process_message(conn, msg)
            except Exception as exc:
                logger.exception("Error processing message, publishing to DLQ")
                await conn.rollback()
                # Publish to DLQ with error details
                try:
                    dlq_payload = {
                        "original_subject": msg.subject,
                        "payload": json.loads(msg.data.decode()) if msg.data else {},
                        "error": str(exc),
                        "retry_count": 0,
                        "first_failed": datetime.now(UTC).isoformat(),
                    }
                    await js.publish(
                        f"dlq.{msg.subject}",
                        json.dumps(dlq_payload, default=str).encode(),
                    )
                except Exception:
                    logger.exception("Failed to publish to DLQ, nacking message")
                await msg.ack()  # Ack original since it's now in DLQ
    finally:
        await conn.close()
        await nc.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(run())
