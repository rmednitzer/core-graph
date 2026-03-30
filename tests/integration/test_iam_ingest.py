"""Integration test: IAM entity and relationship ingest via graph writer.

Requires a running Docker stack (PostgreSQL, NATS).
Marked with @pytest.mark.integration.
"""

from __future__ import annotations

import asyncio
import json

import pytest

pytest_plugins = ["tests.integration.conftest"]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_principal_and_role_merge(pg_conn, nats_conn) -> None:
    """Publish Principal + Role + has_role → verify vertices and edge exist."""
    js = nats_conn.jetstream()

    # Publish Principal vertex
    principal_payload = {
        "label": "Principal",
        "properties": {
            "canonical_key": "test-iam-principal-001",
            "principal_id": "kc-user-001",
            "username": "integration_test_user",
            "email": "test@example.com",
            "enabled": True,
            "created_at": "2024-01-01T00:00:00Z",
            "last_login": "",
            "source": "test",
            "tlp": 2,
        },
    }
    await js.publish(
        "enriched.entity.iam.test",
        json.dumps(principal_payload).encode(),
    )

    # Publish Role vertex
    role_payload = {
        "label": "Role",
        "properties": {
            "canonical_key": "test-iam-role-001",
            "role_name": "test_admin",
            "realm": "test",
            "client_id": "",
            "source": "test",
            "tlp": 2,
        },
    }
    await js.publish(
        "enriched.entity.iam.test",
        json.dumps(role_payload).encode(),
    )

    # Publish has_role relationship
    rel_payload = {
        "type": "has_role",
        "principal_key": "test-iam-principal-001",
        "role_key": "test-iam-role-001",
        "source": "test",
    }
    await js.publish(
        "enriched.relationship.iam.test",
        json.dumps(rel_payload).encode(),
    )

    # Allow time for graph_writer to process messages
    await asyncio.sleep(2)

    # Verify Principal vertex was created
    result = await pg_conn.execute(
        """
        select * from ag_catalog.cypher('core_graph', $$
            match (p:Principal {canonical_key: 'test-iam-principal-001'})
            return p.username, p.tlp_level
        $$) as (username agtype, tlp agtype)
        """
    )
    rows = await result.fetchall()
    assert len(rows) >= 1, "Principal vertex not found in graph"
    assert str(rows[0]["username"]).strip('"') == "integration_test_user"

    # Verify Role vertex was created
    result = await pg_conn.execute(
        """
        select * from ag_catalog.cypher('core_graph', $$
            match (r:Role {canonical_key: 'test-iam-role-001'})
            return r.role_name
        $$) as (role_name agtype)
        """
    )
    rows = await result.fetchall()
    assert len(rows) >= 1, "Role vertex not found in graph"

    # Verify has_role edge was created
    result = await pg_conn.execute(
        """
        select * from ag_catalog.cypher('core_graph', $$
            match (p:Principal {canonical_key: 'test-iam-principal-001'})
                  -[e:has_role]->
                  (r:Role {canonical_key: 'test-iam-role-001'})
            return id(e)
        $$) as (edge_id agtype)
        """
    )
    rows = await result.fetchall()
    assert len(rows) >= 1, "has_role edge not found between Principal and Role"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_iam_tlp_floor_enforced(pg_conn) -> None:
    """IAM vertices must not be visible when app.max_tlp < 2."""
    # Set session to TLP:GREEN (1) — below IAM floor (2)
    await pg_conn.execute("select set_config('app.max_tlp', '1', true)")

    result = await pg_conn.execute(
        """
        select * from ag_catalog.cypher('core_graph', $$
            match (p:Principal)
            return count(p)
        $$) as (cnt agtype)
        """
    )
    rows = await result.fetchall()
    count = int(str(rows[0]["cnt"])) if rows else 0
    assert count == 0, (
        f"IAM vertices visible at TLP:GREEN (app.max_tlp=1): found {count}"
    )

    # Restore to TLP:RED for other tests
    await pg_conn.execute("select set_config('app.max_tlp', '4', true)")
