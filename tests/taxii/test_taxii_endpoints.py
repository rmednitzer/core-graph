"""tests.taxii.test_taxii_endpoints — TAXII 2.1 endpoint unit tests.

Uses FastAPI TestClient with mocked database connections.
No Docker required.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client():
    """Create a test client with mocked dependencies."""
    # Mock the connection pool so we don't need a real database
    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock(return_value=MagicMock(fetchall=AsyncMock(return_value=[])))
    mock_conn.commit = AsyncMock()
    mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_conn.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("api.taxii.server.get_connection", return_value=mock_conn),
        patch("api.db._pool", MagicMock()),
    ):
        from api.rest.main import app

        yield TestClient(app)


class TestDiscovery:
    """Discovery endpoint tests."""

    def test_discovery_returns_valid_structure(self, client: TestClient) -> None:
        resp = client.get("/taxii2/")
        assert resp.status_code == 200
        data = resp.json()
        assert "title" in data
        assert "api_roots" in data
        assert isinstance(data["api_roots"], list)
        assert len(data["api_roots"]) > 0

    def test_discovery_content_type(self, client: TestClient) -> None:
        resp = client.get("/taxii2/")
        assert "application/taxii+json" in resp.headers.get("content-type", "")


class TestAPIRoot:
    """API Root endpoint tests."""

    def test_api_root_returns_info(self, client: TestClient) -> None:
        resp = client.get("/taxii2/default/")
        assert resp.status_code == 200
        data = resp.json()
        assert "title" in data
        assert "versions" in data
        assert "application/taxii+json;version=2.1" in data["versions"]

    def test_unknown_api_root_returns_404(self, client: TestClient) -> None:
        resp = client.get("/taxii2/nonexistent/")
        assert resp.status_code == 404


class TestCollections:
    """Collections endpoint tests."""

    def test_collections_lists_expected(self, client: TestClient) -> None:
        resp = client.get("/taxii2/default/collections/")
        assert resp.status_code == 200
        data = resp.json()
        assert "collections" in data
        ids = {c["id"] for c in data["collections"]}
        assert "threat-intel" in ids
        assert "indicators" in ids
        assert "vulnerabilities" in ids

    def test_single_collection(self, client: TestClient) -> None:
        resp = client.get("/taxii2/default/collections/threat-intel/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "threat-intel"
        assert data["can_read"] is True
        assert data["can_write"] is True

    def test_unknown_collection_returns_404(self, client: TestClient) -> None:
        resp = client.get("/taxii2/default/collections/nonexistent/")
        assert resp.status_code == 404


class TestObjects:
    """Objects endpoint tests."""

    def test_objects_returns_stix_bundle(self, client: TestClient) -> None:
        resp = client.get("/taxii2/default/collections/indicators/objects/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["type"] == "bundle"
        assert "id" in data
        assert data["id"].startswith("bundle--")
        assert "objects" in data
        assert isinstance(data["objects"], list)

    def test_objects_content_type(self, client: TestClient) -> None:
        resp = client.get("/taxii2/default/collections/indicators/objects/")
        assert "application/stix+json" in resp.headers.get("content-type", "")

    def test_objects_added_after_filter(self, client: TestClient) -> None:
        resp = client.get(
            "/taxii2/default/collections/indicators/objects/",
            params={"added_after": "2025-01-01T00:00:00Z"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["type"] == "bundle"

    def test_unknown_collection_objects_returns_404(self, client: TestClient) -> None:
        resp = client.get("/taxii2/default/collections/fake/objects/")
        assert resp.status_code == 404


class TestAddObjects:
    """Add Objects endpoint tests."""

    def test_add_valid_stix_bundle(self, client: TestClient) -> None:
        bundle = {
            "type": "bundle",
            "id": "bundle--test-001",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--test-001",
                    "name": "Test indicator",
                    "pattern": "[ipv4-addr:value = '198.51.100.1']",
                    "pattern_type": "stix",
                    "valid_from": "2025-01-01T00:00:00Z",
                }
            ],
        }
        with patch("api.taxii.server.nats") as mock_nats:
            mock_nc = AsyncMock()
            mock_js = AsyncMock()
            mock_nats.connect = AsyncMock(return_value=mock_nc)
            mock_nc.jetstream = MagicMock(return_value=mock_js)
            mock_js.publish = AsyncMock()
            mock_nc.close = AsyncMock()

            resp = client.post(
                "/taxii2/default/collections/indicators/objects/",
                json=bundle,
            )
        assert resp.status_code == 202
        data = resp.json()
        assert "id" in data
        assert data["status"] == "complete"
        assert data["total_count"] == 1

    def test_add_invalid_bundle_type(self, client: TestClient) -> None:
        resp = client.post(
            "/taxii2/default/collections/indicators/objects/",
            json={"type": "not-a-bundle", "objects": []},
        )
        assert resp.status_code == 422

    def test_add_invalid_json(self, client: TestClient) -> None:
        resp = client.post(
            "/taxii2/default/collections/indicators/objects/",
            content="not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422

    def test_add_missing_objects_field(self, client: TestClient) -> None:
        with patch("api.taxii.server.nats") as mock_nats:
            mock_nc = AsyncMock()
            mock_js = AsyncMock()
            mock_nats.connect = AsyncMock(return_value=mock_nc)
            mock_nc.jetstream = MagicMock(return_value=mock_js)
            mock_js.publish = AsyncMock()
            mock_nc.close = AsyncMock()

            resp = client.post(
                "/taxii2/default/collections/indicators/objects/",
                json={"type": "bundle"},
            )
        assert resp.status_code == 202
        data = resp.json()
        assert data["total_count"] == 0
