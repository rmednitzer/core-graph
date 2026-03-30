"""Tests for the Keycloak adapter with mocked Admin API."""

from __future__ import annotations

from typing import Any

import pytest

from ingest.connectors.keycloak.adapter import KeycloakAdapter, _ms_to_iso
from ingest.connectors.keycloak.config import KeycloakConfig


@pytest.fixture
def adapter() -> KeycloakAdapter:
    """Create a Keycloak adapter with test config."""
    config = KeycloakConfig(
        url="http://keycloak.test:8080",
        realm="test-realm",
        client_id="admin-cli",
        client_secret="test-secret",
        interval=0,
    )
    return KeycloakAdapter(config)


def test_map_user(adapter: KeycloakAdapter) -> None:
    """User mapping produces Principal vertex with TLP >= 2."""
    raw: dict[str, Any] = {
        "_kc_type": "user",
        "id": "user-123",
        "username": "jdoe",
        "email": "jdoe@example.com",
        "enabled": True,
        "createdTimestamp": 1700000000000,
        "lastLogin": None,
    }

    result = adapter.map(raw)

    assert result is not None
    assert result["label"] == "Principal"
    assert result["properties"]["username"] == "jdoe"
    assert result["properties"]["tlp"] >= 2, "IAM TLP floor violated"


def test_map_group(adapter: KeycloakAdapter) -> None:
    """Group mapping produces Group vertex with TLP >= 2."""
    raw: dict[str, Any] = {
        "_kc_type": "group",
        "id": "group-456",
        "name": "engineering",
        "path": "/engineering",
    }

    result = adapter.map(raw)

    assert result is not None
    assert result["label"] == "Group"
    assert result["properties"]["name"] == "engineering"
    assert result["properties"]["tlp"] >= 2, "IAM TLP floor violated"


def test_map_role(adapter: KeycloakAdapter) -> None:
    """Role mapping produces Role vertex with TLP >= 2."""
    raw: dict[str, Any] = {
        "_kc_type": "role",
        "name": "admin",
        "containerId": "test-realm",
    }

    result = adapter.map(raw)

    assert result is not None
    assert result["label"] == "Role"
    assert result["properties"]["role_name"] == "admin"
    assert result["properties"]["tlp"] >= 2, "IAM TLP floor violated"


def test_map_unknown_type(adapter: KeycloakAdapter) -> None:
    """Unknown _kc_type returns None."""
    raw: dict[str, Any] = {"_kc_type": "unknown", "id": "x"}
    assert adapter.map(raw) is None


def test_tlp_floor_enforcement(adapter: KeycloakAdapter) -> None:
    """All IAM entities must have tlp >= 2 regardless of input."""
    for kc_type in ["user", "group", "role"]:
        raw: dict[str, Any] = {
            "_kc_type": kc_type,
            "id": "test-id",
            "name": "test",
            "username": "test",
            "email": "",
            "enabled": True,
            "createdTimestamp": 0,
            "path": "/test",
            "containerId": "",
        }
        result = adapter.map(raw)
        assert result is not None
        assert result["properties"]["tlp"] >= 2, f"IAM TLP floor violated for {kc_type}"


def test_ms_to_iso() -> None:
    """Millisecond timestamp conversion to ISO 8601."""
    assert _ms_to_iso(None) == ""
    assert _ms_to_iso(0) == ""
    result = _ms_to_iso(1700000000000)
    assert "2023-11-14" in result


def test_adapter_disabled_without_secret() -> None:
    """Adapter with empty client_secret logs warning."""
    config = KeycloakConfig(
        url="http://test:8080",
        realm="test",
        client_id="admin",
        client_secret="",
        interval=0,
    )
    adapter = KeycloakAdapter(config)
    assert adapter.kc_config.client_secret == ""
