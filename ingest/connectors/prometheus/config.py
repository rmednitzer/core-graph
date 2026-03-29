"""ingest.connectors.prometheus.config — Configuration for the Prometheus adapter."""

from __future__ import annotations

import os

from pydantic import BaseModel


class PrometheusConfig(BaseModel):
    """Configuration for the AlertManager webhook receiver."""

    host: str = os.environ.get("CG_PROMETHEUS_WEBHOOK_HOST", "0.0.0.0")
    port: int = int(os.environ.get("CG_PROMETHEUS_WEBHOOK_PORT", "9095"))
