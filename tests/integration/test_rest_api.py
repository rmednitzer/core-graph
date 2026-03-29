"""Integration tests for the REST API using FastAPI TestClient."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from api.rest.main import app

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]


@pytest.fixture
def client():
    """Provide a TestClient for the FastAPI app."""
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def test_healthz(client) -> None:
    """GET /healthz returns 200."""
    async with client as c:
        response = await c.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_readyz(client) -> None:
    """GET /readyz returns 200 when stack is up."""
    async with client as c:
        response = await c.get("/readyz")
    assert response.status_code == 200
    data = response.json()
    assert data["postgres"] is True
    assert data["nats"] is True


async def test_post_events_valid(client) -> None:
    """POST /api/v1/events with valid OCSF event returns 200."""
    event = {
        "class_uid": 1,
        "category": "authentication",
        "time": "2026-03-29T12:00:00Z",
        "message": "Test event",
    }
    async with client as c:
        response = await c.post("/api/v1/events", json=event)
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


async def test_post_events_invalid(client) -> None:
    """POST /api/v1/events with invalid event returns 400."""
    event = {"invalid": "missing required fields"}
    async with client as c:
        response = await c.post("/api/v1/events", json=event)
    assert response.status_code == 400


async def test_get_entity_not_found(client) -> None:
    """GET /api/v1/entities/ip/198.51.100.23 returns 404."""
    async with client as c:
        response = await c.get("/api/v1/entities/ip/198.51.100.23")
    assert response.status_code == 404


async def test_post_query_unknown_template(client) -> None:
    """POST /api/v1/query with unknown template returns 400."""
    body = {"template": "nonexistent_query", "params": {}}
    async with client as c:
        response = await c.post("/api/v1/query", json=body)
    assert response.status_code == 400
