"""ingest.connectors.misp.config — Configuration for the MISP adapter.

Mirrors the per-connector Config pattern used by netbox, keycloak, and
prometheus. ADR-0006 documents this as a deliberate convention: each
connector carries its own Config dataclass that re-reads the env so it
can run as a standalone service. Defaults are evaluated at class
definition time, matching the previous module-level os.environ reads.
"""

from __future__ import annotations

import os

from pydantic import BaseModel


class MispConfig(BaseModel):
    """Configuration for the MISP ZMQ feed consumer and REST API."""

    zmq_url: str = os.environ.get("CG_MISP_ZMQ_URL", "tcp://localhost:50000")
    api_url: str = os.environ.get("CG_MISP_API_URL", "https://localhost")
    api_key: str = os.environ.get("CG_MISP_API_KEY", "")
    nats_url: str = os.environ.get("CG_NATS_URL", "nats://localhost:4222")
