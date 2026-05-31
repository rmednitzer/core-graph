"""Integration test: IAM entity and relationship ingest via graph writer.

Requires a running stack (PostgreSQL+AGE, NATS). Marked with
@pytest.mark.integration.
"""

from __future__ import annotations

import json

import pytest

from tests.integration._helpers import poll_cypher

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


async def test_principal_and_role_merge(nats_js, graph_writer, pg_conn) -> None:
    """Publish Principal + Role + has_role → verify vertices and edge exist."""
    principal = {
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
    role = {
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
    await nats_js.publish("enriched.entity.iam.test", json.dumps(principal).encode())
    await nats_js.publish("enriched.entity.iam.test", json.dumps(role).encode())

    # Both endpoints must be written before the edge — the has_role MERGE
    # MATCHes the Principal and Role by canonical_key.
    p_rows = await poll_cypher(
        pg_conn,
        """
        select * from ag_catalog.cypher('core_graph', $$
            match (p:Principal {canonical_key: 'test-iam-principal-001'})
            return p.username, p.tlp_level
        $$) as (username agtype, tlp agtype)
        """,
    )
    assert p_rows, "Principal vertex not found in graph"
    assert str(p_rows[0]["username"]).strip('"') == "integration_test_user"

    r_rows = await poll_cypher(
        pg_conn,
        """
        select * from ag_catalog.cypher('core_graph', $$
            match (r:Role {canonical_key: 'test-iam-role-001'})
            return r.role_name
        $$) as (role_name agtype)
        """,
    )
    assert r_rows, "Role vertex not found in graph"

    rel = {
        "type": "has_role",
        "principal_key": "test-iam-principal-001",
        "role_key": "test-iam-role-001",
        "source": "test",
    }
    await nats_js.publish("enriched.relationship.iam.test", json.dumps(rel).encode())

    edge_rows = await poll_cypher(
        pg_conn,
        """
        select * from ag_catalog.cypher('core_graph', $$
            match (p:Principal {canonical_key: 'test-iam-principal-001'})
                  -[e:has_role]->
                  (r:Role {canonical_key: 'test-iam-role-001'})
            return id(e)
        $$) as (edge_id agtype)
        """,
    )
    assert edge_rows, "has_role edge not found between Principal and Role"


async def test_iam_tlp_floor_enforced(nats_js, graph_writer, pg_conn) -> None:
    """IAM vertices must be invisible to a non-superuser session with max_tlp < 2."""
    principal = {
        "label": "Principal",
        "properties": {
            "canonical_key": "test-iam-floor-001",
            "principal_id": "kc-floor-001",
            "username": "floor_user",
            "email": "floor@example.com",
            "enabled": True,
            "created_at": "2024-01-01T00:00:00Z",
            "last_login": "",
            "source": "test",
            "tlp": 2,
        },
    }
    await nats_js.publish("enriched.entity.iam.test", json.dumps(principal).encode())
    await poll_cypher(
        pg_conn,
        """
        select * from ag_catalog.cypher('core_graph', $$
            match (p:Principal {canonical_key: 'test-iam-floor-001'})
            return p.username
        $$) as (username agtype)
        """,
    )

    # A superuser bypasses RLS, so the floor is checked under a non-superuser
    # role. cg_soc_analyst holds table-level SELECT on the IAM tables but the
    # migrations grant no schema USAGE (the app's read/write path is the
    # cg_admin superuser); grant it here as test setup so the role can reach the
    # table and the RESTRICTIVE TLP:AMBER floor (migration 010) — not a missing
    # privilege — is what hides IAM rows when app.max_tlp < 2.
    await pg_conn.execute("grant usage on schema core_graph, ag_catalog to cg_soc_analyst")
    await pg_conn.execute("set role cg_soc_analyst")
    await pg_conn.execute("select set_config('app.max_tlp', '1', false)")
    try:
        cur = await pg_conn.execute(
            'select count(*) as n from core_graph."Principal" '
            "where (properties::text)::jsonb->>'canonical_key' = 'test-iam-floor-001'"
        )
        row = await cur.fetchone()
    finally:
        await pg_conn.execute("reset role")
        await pg_conn.execute("select set_config('app.max_tlp', '4', false)")
    assert row["n"] == 0, "IAM Principal visible at TLP:GREEN — AMBER floor violated"
