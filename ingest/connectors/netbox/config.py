"""ingest.connectors.netbox.config — Configuration for the Netbox adapter."""

from __future__ import annotations

import os

from pydantic import BaseModel


class NetboxConfig(BaseModel):
    """Configuration for Netbox REST API polling."""

    url: str = os.environ.get("NETBOX_URL", "http://localhost:8080")
    token: str = os.environ.get("NETBOX_TOKEN", "")
    interval: int = 300
    verify_ssl: bool = True


# Netbox API endpoints to sync and their graph label mappings.
ENDPOINT_LABEL_MAP: dict[str, str] = {
    "/api/dcim/devices/": "Host",
    "/api/virtualization/virtual-machines/": "Host",
    "/api/ipam/prefixes/": "Network",
    "/api/dcim/sites/": "Site",
    "/api/dcim/interfaces/": "Interface",
    "/api/ipam/services/": "Service",
}
