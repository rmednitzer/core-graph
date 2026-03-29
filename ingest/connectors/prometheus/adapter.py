"""ingest.connectors.prometheus.adapter — Prometheus AlertManager webhook adapter.

Receives AlertManager webhook POST payloads and publishes MonitoringAlert
entities to NATS JetStream for graph writer consumption.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any

import nats
import uvicorn
from nats.js.api import StreamConfig
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from api.config import NATS_URL
from ingest.connectors.prometheus.config import PrometheusConfig

logger = logging.getLogger(__name__)

NATS_SUBJECT = "ingest.monitoring.prometheus"
DEFAULT_TLP = 1  # TLP:GREEN — monitoring alerts

# Matches an IP (v4) optionally followed by :port
_IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?")


def _extract_instance_ip(instance: str) -> str | None:
    """Extract the bare IP address from an AlertManager instance label."""
    m = _IP_RE.match(instance)
    return m.group(1) if m else None


def _map_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Map a single AlertManager alert to a MonitoringAlert entity."""
    labels = alert.get("labels", {})
    return {
        "label": "MonitoringAlert",
        "properties": {
            "fingerprint": alert.get("fingerprint", ""),
            "alertname": labels.get("alertname", ""),
            "severity": labels.get("severity", "warning"),
            "status": alert.get("status", "firing"),
            "instance": labels.get("instance", ""),
            "tlp": DEFAULT_TLP,
            "starts_at": alert.get("startsAt"),
            "ends_at": alert.get("endsAt"),
        },
    }


def _build_app(js_holder: dict[str, Any]) -> Starlette:
    """Build the Starlette app with the webhook endpoint."""

    async def webhook(request: Request) -> JSONResponse:
        """Handle AlertManager webhook POST."""
        try:
            payload = await request.json()
        except Exception:
            logger.warning("Invalid JSON in webhook payload")
            return JSONResponse({"error": "invalid json"}, status_code=400)

        alerts = payload.get("alerts", [])
        js = js_holder["js"]
        published = 0

        for alert in alerts:
            entity = _map_alert(alert)
            await js.publish(
                NATS_SUBJECT,
                json.dumps(entity, default=str).encode(),
            )
            published += 1

            # Also publish a CanonicalIP if we can extract one.
            instance = alert.get("labels", {}).get("instance", "")
            ip = _extract_instance_ip(instance)
            if ip:
                ip_entity = {
                    "label": "CanonicalIP",
                    "properties": {"value": ip, "tlp": DEFAULT_TLP},
                }
                await js.publish(
                    NATS_SUBJECT,
                    json.dumps(ip_entity, default=str).encode(),
                )

        logger.info("Webhook received %d alerts, published %d entities", len(alerts), published)
        return JSONResponse({"accepted": published})

    async def health(request: Request) -> JSONResponse:
        """Health check endpoint."""
        return JSONResponse({"status": "ok"})

    return Starlette(
        routes=[
            Route("/webhook", webhook, methods=["POST"]),
            Route("/health", health, methods=["GET"]),
        ],
    )


async def run(
    config: PrometheusConfig | None = None,
    nats_url: str | None = None,
) -> None:
    """Start the AlertManager webhook receiver."""
    cfg = config or PrometheusConfig()
    nats_addr = nats_url or NATS_URL

    nc = await nats.connect(nats_addr)
    js = nc.jetstream()

    await js.add_stream(
        StreamConfig(
            name="INGEST_MONITORING",
            subjects=["ingest.monitoring.>"],
            retention="limits",
            max_bytes=1_073_741_824,
        )
    )

    js_holder: dict[str, Any] = {"js": js}
    app = _build_app(js_holder)

    server_config = uvicorn.Config(
        app,
        host=cfg.host,
        port=cfg.port,
        log_level="info",
    )
    server = uvicorn.Server(server_config)

    logger.info(
        "Prometheus webhook adapter started on %s:%d, NATS=%s",
        cfg.host,
        cfg.port,
        nats_addr,
    )

    try:
        await server.serve()
    finally:
        await nc.close()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
    )
    asyncio.run(run())
