"""api.mcp.tools.identity_attribution — Principal-to-ThreatActor attribution.

Creates a same_as edge between a Principal and a ThreatActor vertex.
Requires cg_ciso role via Cerbos. Never callable by cg_ai_agent.
Creates TLP:RED edges with compartment scoping to investigation_id.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from api.config import CERBOS_ENDPOINT, DEFAULT_TLP
from api.db import get_connection

logger = logging.getLogger(__name__)


async def _check_cerbos_authorization(
    caller_identity: dict[str, Any],
    resource_id: str,
) -> bool:
    """Check Cerbos authorization for identity attribution.

    Fail closed: deny if Cerbos is unreachable.
    """
    import httpx

    principal = {
        "id": caller_identity.get("actor", "unknown"),
        "roles": caller_identity.get("roles", []),
        "attr": caller_identity.get("attr", {}),
    }
    resource = {
        "kind": "identity_attribution",
        "id": resource_id,
        "attr": {},
    }
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(
                f"{CERBOS_ENDPOINT}/api/check/resources",
                json={
                    "principal": principal,
                    "resources": [
                        {"resource": resource, "actions": ["assert"]}
                    ],
                },
            )
            resp.raise_for_status()
            result = resp.json()

            # Parse Cerbos response
            results = result.get("results", [])
            if not results:
                logger.warning("Empty Cerbos response for identity_attribution")
                return False
            actions = results[0].get("actions", {})
            return actions.get("assert", {}).get("effect") == "EFFECT_ALLOW"
    except Exception:
        logger.error(
            "Cerbos unreachable, denying identity_attribution (fail closed)",
            exc_info=True,
        )
        return False


async def assert_identity_attribution(
    principal_id: str,
    threat_actor_stix_id: str,
    justification: str,
    investigation_id: str,
    caller_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a same_as edge between a Principal and a ThreatActor.

    Requires cg_ciso role (checked via Cerbos before any DB operation).
    Creates TLP:RED edge with compartment set to investigation_id.

    Args:
        principal_id: The Keycloak principal ID.
        threat_actor_stix_id: The STIX ID of the threat actor.
        justification: Mandatory justification for the attribution.
        investigation_id: Investigation compartment for the edge.
        caller_identity: MCP session context (must include ciso role).

    Returns:
        Dict with edge_id and audit correlation_id.

    Raises:
        PermissionError: If Cerbos denies the action.
    """
    caller = caller_identity or {"max_tlp": DEFAULT_TLP, "allowed_compartments": []}

    # Cerbos check — fail closed
    resource_id = f"{principal_id}:{threat_actor_stix_id}"
    authorized = await _check_cerbos_authorization(caller, resource_id)
    if not authorized:
        raise PermissionError(
            "Identity attribution requires cg_ciso role. "
            "Denied by Cerbos policy."
        )

    correlation_id = uuid.uuid4()

    from ingest.canonical import canonical_key

    principal_key = canonical_key("principal", principal_id)

    from datetime import UTC, datetime

    async with get_connection(caller) as conn:
        # Create same_as edge with TLP:RED and compartment.
        # Cypher is a constant string — parameters bound via AGE JSON mechanism.
        params = {
            "principal_key": principal_key,
            "threat_actor_stix_id": threat_actor_stix_id,
            "investigation_id": investigation_id,
            "justification": justification,
            "now": datetime.now(UTC).isoformat(),
        }
        agtype_params = json.dumps(params)

        sql = """
            select * from ag_catalog.cypher('core_graph', $cypher$
                match (p:Principal {canonical_key: $principal_key})
                match (ta:ThreatActor {stix_id: $threat_actor_stix_id})
                merge (p)-[e:same_as {
                    investigation_id: $investigation_id,
                    justification: $justification,
                    tlp_level: 4,
                    compartment: $investigation_id,
                    t_recorded: $now
                }]->(ta)
                return id(e)
            $cypher$, %s) as (id agtype)
        """
        cursor = await conn.execute(sql, (agtype_params,))
        result = await cursor.fetchone()
        edge_id = int(str(result["id"]).strip('"')) if result else None

        # Write mandatory audit log entry with justification
        await conn.execute(
            """
            insert into audit_log
                (entity_id, entity_label, operation, actor,
                 correlation_id, new_value_hash)
            values (%s, %s, %s, %s, %s, %s)
            """,
            (
                edge_id,
                "same_as:Principal-ThreatActor",
                "IDENTITY_ATTRIBUTION",
                caller.get("actor", "unknown"),
                correlation_id,
                f"principal={principal_id} threat_actor={threat_actor_stix_id} "
                f"investigation={investigation_id} justification={justification}",
            ),
        )
        await conn.commit()

    logger.info(
        "Identity attribution created: principal=%s threat_actor=%s "
        "investigation=%s correlation=%s",
        principal_id,
        threat_actor_stix_id,
        investigation_id,
        correlation_id,
    )

    return {
        "edge_id": edge_id,
        "correlation_id": str(correlation_id),
    }
