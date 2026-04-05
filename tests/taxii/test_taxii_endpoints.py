"""tests.taxii.test_taxii_endpoints — TAXII 2.1 endpoint unit tests.

Uses FastAPI TestClient with mocked database connections.
No Docker required.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def mock_conn():
    """Create a mock connection for asserting query args."""
    conn = AsyncMock()
    conn.execute = AsyncMock(
        return_value=MagicMock(
            fetchall=AsyncMock(return_value=[]),
            fetchone=AsyncMock(return_value=None),
        )
    )
    conn.commit = AsyncMock()
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=False)
    return conn


@pytest.fixture()
def client(mock_conn):
    """Create a test client with mocked dependencies."""
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

    def test_objects_match_type_filter(self, client: TestClient, mock_conn: AsyncMock) -> None:
        """match[type] parameter is forwarded to the Cypher query, not filtered in Python."""
        resp = client.get(
            "/taxii2/default/collections/threat-intel/objects/",
            params={"match[type]": "threat-actor"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["type"] == "bundle"
        # The second execute call (after audit write) builds the objects query
        calls = mock_conn.execute.call_args_list
        objects_call = calls[-1]
        query_text = objects_call[0][0]
        assert "v.stix_type = $match_type" in query_text

    def test_objects_match_id_filter(self, client: TestClient, mock_conn: AsyncMock) -> None:
        """match[id] parameter filters server-side via Cypher WHERE clause."""
        resp = client.get(
            "/taxii2/default/collections/indicators/objects/",
            params={"match[id]": "indicator--nonexistent"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["type"] == "bundle"
        assert len(data["objects"]) == 0
        # Verify the id filter clause is in the query
        calls = mock_conn.execute.call_args_list
        objects_call = calls[-1]
        query_text = objects_call[0][0]
        assert "v.stix_id = $match_id" in query_text

    def test_objects_pagination_more_flag_empty(self, client: TestClient) -> None:
        """With no results, more should be absent or false."""
        resp = client.get(
            "/taxii2/default/collections/indicators/objects/",
            params={"limit": 1},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["type"] == "bundle"
        assert data.get("more", False) is False

    def test_objects_pagination_more_flag_full(self) -> None:
        """When DB returns limit+1 rows, more is true and results are truncated."""
        import json as _json

        # Create limit+1 = 2 mock rows so the server sees overflow
        mock_rows = [
            {"props": _json.dumps({"stix_id": "ind--1", "t_recorded": "2025-01-01T00:00:00Z"})},
            {"props": _json.dumps({"stix_id": "ind--2", "t_recorded": "2025-01-02T00:00:00Z"})},
        ]
        conn = AsyncMock()
        conn.execute = AsyncMock(
            return_value=MagicMock(
                fetchall=AsyncMock(return_value=mock_rows),
                fetchone=AsyncMock(return_value=None),
            )
        )
        conn.commit = AsyncMock()
        conn.__aenter__ = AsyncMock(return_value=conn)
        conn.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("api.taxii.server.get_connection", return_value=conn),
            patch("api.db._pool", MagicMock()),
        ):
            from api.rest.main import app

            tc = TestClient(app)
            resp = tc.get(
                "/taxii2/default/collections/indicators/objects/",
                params={"limit": 1},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["type"] == "bundle"
        assert data["more"] is True
        assert "next" in data
        # next is now a t_recorded cursor, not an integer offset
        assert data["next"] == "2025-01-01T00:00:00Z"
        assert len(data["objects"]) == 1

    def test_cursor_pagination_no_duplicates(self) -> None:
        """Keyset pagination across 3 pages produces no duplicate objects."""
        import json as _json

        all_objects: list[dict] = []

        # Page 1: 2 rows (limit=1 + 1 overflow)
        page1_rows = [
            {"props": _json.dumps({"stix_id": "ind--1", "t_recorded": "2025-01-01T00:00:00Z"})},
            {"props": _json.dumps({"stix_id": "ind--2", "t_recorded": "2025-01-02T00:00:00Z"})},
        ]
        # Page 2: 2 rows
        page2_rows = [
            {"props": _json.dumps({"stix_id": "ind--3", "t_recorded": "2025-01-03T00:00:00Z"})},
            {"props": _json.dumps({"stix_id": "ind--4", "t_recorded": "2025-01-04T00:00:00Z"})},
        ]
        # Page 3: 1 row (no overflow, last page)
        page3_rows = [
            {"props": _json.dumps({"stix_id": "ind--5", "t_recorded": "2025-01-05T00:00:00Z"})},
        ]

        pages = [page1_rows, page2_rows, page3_rows]
        cursor = None

        for page_rows in pages:
            conn = AsyncMock()
            conn.execute = AsyncMock(
                return_value=MagicMock(
                    fetchall=AsyncMock(return_value=page_rows),
                    fetchone=AsyncMock(return_value=None),
                )
            )
            conn.commit = AsyncMock()
            conn.__aenter__ = AsyncMock(return_value=conn)
            conn.__aexit__ = AsyncMock(return_value=False)

            with (
                patch("api.taxii.server.get_connection", return_value=conn),
                patch("api.db._pool", MagicMock()),
            ):
                from api.rest.main import app

                tc = TestClient(app)
                params: dict = {"limit": 1}
                if cursor:
                    params["next"] = cursor

                resp = tc.get(
                    "/taxii2/default/collections/indicators/objects/",
                    params=params,
                )

            assert resp.status_code == 200
            data = resp.json()
            all_objects.extend(data["objects"])

            if data.get("more"):
                cursor = data["next"]
            else:
                break

        # Verify no duplicates
        stix_ids = [o["stix_id"] for o in all_objects]
        assert len(stix_ids) == len(set(stix_ids)), (
            f"Duplicate objects found in pagination: {stix_ids}"
        )


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
