"""Tests for AdapterBase."""

from __future__ import annotations

from typing import Any

from ingest.connectors.base import AdapterBase, AdapterConfig


class ConcreteAdapter(AdapterBase):
    """Minimal concrete adapter for testing."""

    async def fetch(self, since: str | None) -> list[dict[str, Any]]:
        return [{"id": 1, "name": "test"}]

    def map(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        return {
            "label": "TestEntity",
            "properties": {"name": raw["name"], "tlp": 1},
        }


def test_adapter_config() -> None:
    """AdapterConfig stores all required fields."""
    config = AdapterConfig(
        name="test",
        nats_subject="enriched.entity.test",
        nats_stream="ENRICHED",
        poll_interval=60,
        default_tlp=1,
        delta_sync=True,
    )
    assert config.name == "test"
    assert config.delta_sync is True


def test_concrete_adapter_map() -> None:
    """Concrete adapter maps raw data to entity payload."""
    config = AdapterConfig(
        name="test",
        nats_subject="enriched.entity.test",
        nats_stream="ENRICHED",
        poll_interval=0,
        default_tlp=1,
        delta_sync=False,
    )
    adapter = ConcreteAdapter(config)
    result = adapter.map({"id": 1, "name": "server-01"})
    assert result is not None
    assert result["label"] == "TestEntity"
    assert result["properties"]["name"] == "server-01"


def test_concrete_adapter_map_none() -> None:
    """Map can return None to skip records."""

    class SkippingAdapter(AdapterBase):
        async def fetch(self, since: str | None) -> list[dict[str, Any]]:
            return []

        def map(self, raw: dict[str, Any]) -> dict[str, Any] | None:
            return None

    config = AdapterConfig(
        name="skip",
        nats_subject="enriched.entity.skip",
        nats_stream="ENRICHED",
        poll_interval=0,
        default_tlp=1,
        delta_sync=False,
    )
    adapter = SkippingAdapter(config)
    assert adapter.map({"anything": True}) is None
