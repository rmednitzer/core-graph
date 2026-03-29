"""ingest.connectors.netbox.adapter — Netbox CMDB/IPAM ingest adapter.

Periodically polls the Netbox REST API for devices, VMs, prefixes, sites,
interfaces, and services.  Publishes normalised entities to the NATS
``enriched.entity.*`` stream for direct graph writer consumption.
Uses Valkey for delta-sync caching. Extends AdapterBase.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from ingest.canonical import canonical_key
from ingest.connectors.base import AdapterBase, AdapterConfig
from ingest.connectors.netbox.config import NetboxConfig

logger = logging.getLogger(__name__)

NATS_SUBJECT = "enriched.entity.infra.netbox"
DEFAULT_TLP = 1  # TLP:GREEN — infrastructure inventory


# -- Entity mapping ----------------------------------------------------------


def _map_device(obj: dict[str, Any]) -> dict[str, Any]:
    """Map a Netbox device to a Host entity."""
    name = obj.get("name") or obj.get("display", "")
    netbox_id = obj["id"]
    return {
        "label": "Host",
        "properties": {
            "canonical_key": canonical_key("host", f"netbox-{netbox_id}"),
            "name": name,
            "host_type": "device",
            "platform": (obj.get("platform") or {}).get("slug", ""),
            "status": (obj.get("status") or {}).get("value", "active"),
            "site": (obj.get("site") or {}).get("slug", ""),
            "netbox_id": netbox_id,
            "primary_ip": _extract_ip(obj.get("primary_ip")),
            "tlp": DEFAULT_TLP,
        },
    }


def _map_vm(obj: dict[str, Any]) -> dict[str, Any]:
    """Map a Netbox virtual machine to a Host entity."""
    name = obj.get("name") or obj.get("display", "")
    netbox_id = obj["id"]
    return {
        "label": "Host",
        "properties": {
            "canonical_key": canonical_key("host", f"netbox-vm-{netbox_id}"),
            "name": name,
            "host_type": "vm",
            "platform": (obj.get("platform") or {}).get("slug", ""),
            "status": (obj.get("status") or {}).get("value", "active"),
            "site": (obj.get("site") or {}).get("slug", ""),
            "netbox_id": netbox_id,
            "primary_ip": _extract_ip(obj.get("primary_ip")),
            "tlp": DEFAULT_TLP,
        },
    }


def _map_prefix(obj: dict[str, Any]) -> dict[str, Any]:
    """Map a Netbox prefix to a Network entity."""
    return {
        "label": "Network",
        "properties": {
            "prefix": obj.get("prefix", ""),
            "vlan_id": (obj.get("vlan") or {}).get("vid"),
            "site": (obj.get("site") or {}).get("slug", ""),
            "description": obj.get("description", ""),
            "tlp": DEFAULT_TLP,
        },
    }


def _map_site(obj: dict[str, Any]) -> dict[str, Any]:
    """Map a Netbox site to a Site entity."""
    return {
        "label": "Site",
        "properties": {
            "name": obj.get("name", ""),
            "slug": obj.get("slug", ""),
            "region": (obj.get("region") or {}).get("slug", ""),
            "tlp": DEFAULT_TLP,
        },
    }


def _map_interface(obj: dict[str, Any]) -> dict[str, Any]:
    """Map a Netbox interface to an Interface entity."""
    netbox_id = obj["id"]
    return {
        "label": "Interface",
        "properties": {
            "canonical_key": canonical_key("interface", f"netbox-{netbox_id}"),
            "name": obj.get("name", ""),
            "mac_address": obj.get("mac_address") or "",
            "enabled": obj.get("enabled", True),
            "tlp": DEFAULT_TLP,
        },
    }


def _map_service(obj: dict[str, Any]) -> dict[str, Any]:
    """Map a Netbox service to a Service entity."""
    netbox_id = obj["id"]
    return {
        "label": "Service",
        "properties": {
            "canonical_key": canonical_key("service", f"netbox-{netbox_id}"),
            "name": obj.get("name", ""),
            "protocol": (obj.get("protocol") or {}).get("value", ""),
            "ports": obj.get("ports") or [],
            "tlp": DEFAULT_TLP,
        },
    }


def _extract_ip(ip_obj: dict[str, Any] | None) -> str:
    """Extract bare IP address from a Netbox primary_ip object."""
    if not ip_obj:
        return ""
    addr = ip_obj.get("address", "")
    # Netbox returns CIDR notation (e.g. "10.0.0.5/24"), strip the mask.
    return addr.split("/")[0] if addr else ""


ENDPOINT_MAPPERS: dict[str, Any] = {
    "/api/dcim/devices/": _map_device,
    "/api/virtualization/virtual-machines/": _map_vm,
    "/api/ipam/prefixes/": _map_prefix,
    "/api/dcim/sites/": _map_site,
    "/api/dcim/interfaces/": _map_interface,
    "/api/ipam/services/": _map_service,
}


class NetboxAdapter(AdapterBase):
    """Netbox CMDB/IPAM adapter using AdapterBase."""

    def __init__(self, config: NetboxConfig | None = None) -> None:
        self.netbox_config = config or NetboxConfig()
        super().__init__(
            AdapterConfig(
                name="netbox",
                nats_subject=NATS_SUBJECT,
                nats_stream="ENRICHED",
                poll_interval=self.netbox_config.interval,
                default_tlp=DEFAULT_TLP,
                delta_sync=True,
            )
        )
        self._http_client: httpx.AsyncClient | None = None

    async def fetch(self, since: str | None) -> list[dict[str, Any]]:
        """Fetch all objects from all Netbox endpoints."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                verify=self.netbox_config.verify_ssl
            )

        all_objects: list[dict[str, Any]] = []
        for endpoint in ENDPOINT_MAPPERS:
            objects = await self._fetch_endpoint(endpoint, since)
            # Tag each object with its source endpoint for map()
            for obj in objects:
                obj["_endpoint"] = endpoint
            all_objects.extend(objects)
        return all_objects

    def map(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        """Map a Netbox object to a graph entity payload."""
        endpoint = raw.pop("_endpoint", "")
        mapper = ENDPOINT_MAPPERS.get(endpoint)
        if mapper is None:
            return None
        entity = mapper(raw)

        # Also publish a CanonicalIP if the entity has a primary IP.
        # The base class publish handles a single entity, so we store
        # extra entities to be published by the overridden run loop.
        primary_ip = entity.get("properties", {}).get("primary_ip", "")
        if primary_ip:
            self._pending_ip_entities.append({
                "label": "CanonicalIP",
                "properties": {
                    "value": primary_ip,
                    "tlp": DEFAULT_TLP,
                },
            })
        return entity

    async def run(
        self,
        nats_url: str | None = None,
        valkey_url: str | None = None,
        pg_dsn: str | None = None,
    ) -> None:
        """Override run to handle CanonicalIP side-publishing."""
        self._pending_ip_entities: list[dict[str, Any]] = []

        # Store original _publish to wrap it
        original_publish = self._publish

        async def _publish_with_ips(entity: dict[str, Any]) -> None:
            await original_publish(entity)
            # Publish any pending IP entities
            while self._pending_ip_entities:
                ip_entity = self._pending_ip_entities.pop(0)
                await original_publish(ip_entity)

        self._publish = _publish_with_ips  # type: ignore[assignment]

        try:
            await super().run(nats_url, valkey_url, pg_dsn)
        finally:
            if self._http_client:
                await self._http_client.aclose()

    async def _fetch_endpoint(
        self,
        endpoint: str,
        since: str | None,
    ) -> list[dict[str, Any]]:
        """Fetch all objects from a paginated Netbox endpoint."""
        if self._http_client is None:
            return []

        # Use per-endpoint delta sync from Valkey
        cache_key = f"netbox:sync:{endpoint}:last_modified"
        last_modified = None
        if self._cache and since:
            raw = await self._cache.get(cache_key)
            if raw:
                last_modified = raw.decode()

        url = f"{self.netbox_config.url.rstrip('/')}{endpoint}"
        params: dict[str, Any] = {"limit": 100, "offset": 0}
        if last_modified:
            params["modified_after"] = last_modified

        headers = {
            "Authorization": f"Token {self.netbox_config.token}",
            "Accept": "application/json",
        }
        results: list[dict[str, Any]] = []

        while True:
            try:
                resp = await self._http_client.get(
                    url, params=params, headers=headers, timeout=30
                )
                resp.raise_for_status()
            except httpx.HTTPError:
                self._logger.warning("Netbox %s: fetch failed", endpoint, exc_info=True)
                break

            body = resp.json()
            page_results = body.get("results", [])
            results.extend(page_results)

            if not body.get("next"):
                break
            params["offset"] += params["limit"]

        # Update per-endpoint cache timestamp
        if results and self._cache:
            from datetime import UTC, datetime

            await self._cache.set(cache_key, datetime.now(UTC).isoformat())

        return results


async def run(
    config: NetboxConfig | None = None,
    nats_url: str | None = None,
    valkey_url: str | None = None,
    pg_dsn: str | None = None,
) -> None:
    """Backward-compatible entry point."""
    adapter = NetboxAdapter(config)
    await adapter.run(nats_url, valkey_url, pg_dsn)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    asyncio.run(run())
