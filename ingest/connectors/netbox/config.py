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
