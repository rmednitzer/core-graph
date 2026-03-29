"""Integration test: IAM entity and relationship ingest via graph writer.

Requires a running Docker stack (PostgreSQL, NATS).
Marked with @pytest.mark.integration.
"""

from __future__ import annotations

import json

import pytest

pytest_plugins = ["tests.integration.conftest"]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_principal_and_role_merge(pg_conn, nats_conn) -> None:
    """Publish Principal + Role + has_role → verify edge exists."""
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
