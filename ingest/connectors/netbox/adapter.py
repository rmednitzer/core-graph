"""ingest.connectors.netbox.adapter — Netbox CMDB/IPAM ingest adapter.

Periodically polls the Netbox REST API for devices, VMs, prefixes, sites,
interfaces, and services.  Publishes normalised entities to NATS JetStream
for graph writer consumption.  Uses Valkey for delta-sync caching.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import nats
import psycopg
import redis.asyncio as redis
from nats.js.api import StreamConfig

from api.config import NATS_URL, PG_DSN, VALKEY_URL
from ingest.canonical import canonical_key
from ingest.connectors.netbox.config import ENDPOINT_LABEL_MAP, NetboxConfig

logger = logging.getLogger(__name__)

NATS_SUBJECT = "ingest.infra.netbox"
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
            "ports": json.dumps(obj.get("ports", [])),
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


_ENDPOINT_MAPPERS: dict[str, Any] = {
    "/api/dcim/devices/": _map_device,
    "/api/virtualization/virtual-machines/": _map_vm,
    "/api/ipam/prefixes/": _map_prefix,
    "/api/dcim/sites/": _map_site,
    "/api/dcim/interfaces/": _map_interface,
    "/api/ipam/services/": _map_service,
}


# -- Fetching ----------------------------------------------------------------


async def _fetch_endpoint(
    client: httpx.AsyncClient,
    base_url: str,
    endpoint: str,
    token: str,
    cache: redis.Redis,
) -> list[dict[str, Any]]:
    """Fetch all objects from a paginated Netbox endpoint.

    Uses Valkey to cache the last sync timestamp per endpoint so only
    objects modified since the last run are returned.
    """
    cache_key = f"netbox:sync:{endpoint}:last_modified"
    last_modified = await cache.get(cache_key)

    url = f"{base_url.rstrip('/')}{endpoint}"
    params: dict[str, Any] = {"limit": 100, "offset": 0}
    if last_modified:
        params["modified_after"] = last_modified.decode()

    headers = {"Authorization": f"Token {token}", "Accept": "application/json"}
    results: list[dict[str, Any]] = []

    while True:
        try:
            resp = await client.get(url, params=params, headers=headers, timeout=30)
            resp.raise_for_status()
        except httpx.HTTPError:
            logger.warning("Netbox %s: fetch failed", endpoint, exc_info=True)
            break

        body = resp.json()
        page_results = body.get("results", [])
        results.extend(page_results)

        if not body.get("next"):
            break
        params["offset"] += params["limit"]

    # Update cache timestamp for next delta sync.
    if results:
        await cache.set(cache_key, datetime.now(UTC).isoformat())

    return results


# -- Publishing --------------------------------------------------------------


async def _publish_entities(
    js: nats.js.JetStreamContext,
    endpoint: str,
    objects: list[dict[str, Any]],
) -> int:
    """Map Netbox objects to graph entities and publish to NATS."""
    mapper = _ENDPOINT_MAPPERS.get(endpoint)
    if not mapper:
        return 0

    count = 0
    for obj in objects:
        entity = mapper(obj)
        await js.publish(
            NATS_SUBJECT,
            json.dumps(entity, default=str).encode(),
        )
        count += 1

        # Also publish a CanonicalIP if the entity has a primary IP.
        primary_ip = entity.get("properties", {}).get("primary_ip", "")
        if primary_ip:
            ip_entity = {
                "label": "CanonicalIP",
                "properties": {
                    "value": primary_ip,
                    "tlp": DEFAULT_TLP,
                },
            }
            await js.publish(
                NATS_SUBJECT,
                json.dumps(ip_entity, default=str).encode(),
            )

    return count


# -- Audit -------------------------------------------------------------------


async def _write_audit_entry(
    pg_dsn: str,
    entity_count: int,
    endpoint: str,
) -> None:
    """Log sync cycle to the audit trail."""
    try:
        async with await psycopg.AsyncConnection.connect(pg_dsn) as conn:
            await conn.execute(
                """
                insert into audit_log
                    (entity_label, operation, actor, correlation_id)
                values (%s, %s, %s, %s)
                """,
                (
                    f"netbox:{endpoint}",
                    "SYNC",
                    "netbox_adapter",
                    uuid.uuid4(),
                ),
            )
            await conn.commit()
    except Exception:
        logger.warning(
            "Failed to write audit entry for endpoint %s",
            endpoint,
            exc_info=True,
        )


# -- Main loop ---------------------------------------------------------------


async def run(
    config: NetboxConfig | None = None,
    nats_url: str | None = None,
    valkey_url: str | None = None,
    pg_dsn: str | None = None,
) -> None:
    """Main loop: periodically sync Netbox objects into the graph."""
    cfg = config or NetboxConfig()
    nats_addr = nats_url or NATS_URL
    valkey_addr = valkey_url or VALKEY_URL
    dsn = pg_dsn or PG_DSN

    nc = await nats.connect(nats_addr)
    js = nc.jetstream()

    await js.add_stream(
        StreamConfig(
            name="INGEST_INFRA",
            subjects=["ingest.infra.>"],
            retention="limits",
            max_bytes=1_073_741_824,
        )
    )

    cache = redis.from_url(valkey_addr)

    logger.info(
        "Netbox adapter started, url=%s, interval=%ds, NATS=%s",
        cfg.url,
        cfg.interval,
        nats_addr,
    )

    try:
        async with httpx.AsyncClient(verify=cfg.verify_ssl) as client:
            while True:
                total = 0
                for endpoint in ENDPOINT_LABEL_MAP:
                    objects = await _fetch_endpoint(
                        client,
                        cfg.url,
                        endpoint,
                        cfg.token,
                        cache,
                    )
                    if objects:
                        count = await _publish_entities(js, endpoint, objects)
                        total += count
                        await _write_audit_entry(dsn, count, endpoint)
                        logger.info(
                            "Netbox %s: published %d entities",
                            endpoint,
                            count,
                        )

                logger.info("Netbox sync cycle complete: %d entities total", total)
                await asyncio.sleep(cfg.interval)
    finally:
        await cache.aclose()
        await nc.close()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    asyncio.run(run())
