"""Tests for label safety in entity_resolve and stix_lookup tools."""

import pytest

from api.mcp.tools.entity_resolve import entity_resolve
from api.mcp.tools.stix_lookup import stix_lookup


@pytest.mark.asyncio
async def test_entity_resolve_rejects_unknown_type() -> None:
    with pytest.raises(ValueError, match="Unknown IOC type"):
        await entity_resolve("malicious_type'; DROP", "value")


@pytest.mark.asyncio
async def test_stix_lookup_rejects_unknown_type() -> None:
    with pytest.raises(ValueError, match="Unknown STIX type"):
        await stix_lookup("not-a-type", "id-value")
