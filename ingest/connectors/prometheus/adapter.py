"""ingest.connectors.prometheus.adapter — Prometheus AlertManager webhook adapter.

Receives AlertManager webhook POST payloads and publishes MonitoringAlert
entities to the NATS ``enriched.entity.*`` stream for direct graph writer
consumption.  Supports optional shared-secret authentication.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
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

NATS_SUBJECT = "enriched.entity.monitoring.prometheus"
DEFAULT_TLP = 1  # TLP:GREEN — monitoring alerts

# AlertManager uses this as a sentinel for "no end yet" on firing alerts.
_ALERTMANAGER_SENTINEL_END = "0001-01-01T00:00:00Z"

# Matches an IP (v4) optionally followed by :port
_IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?")

# Optional shared secret for webhook authentication.
WEBHOOK_SECRET = os.environ.get("CG_PROMETHEUS_WEBHOOK_SECRET", "")


def _extract_instance_ip(instance: str) -> str | None:
    """Extract the bare IP address from an AlertManager instance label."""
    m = _IP_RE.match(instance)
    return m.group(1) if m else None


def _map_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Map a single AlertManager alert to a MonitoringAlert entity."""
    labels = alert.get("labels", {})

    # Normalize endsAt: treat the AlertManager sentinel as None.
    raw_ends_at = alert.get("endsAt")
    if not raw_ends_at or raw_ends_at == _ALERTMANAGER_SENTINEL_END:
        ends_at: str | None = None
    else:
        ends_at = raw_ends_at

    properties: dict[str, Any] = {
        "fingerprint": alert.get("fingerprint", ""),
        "alertname": labels.get("alertname", ""),
        "severity": labels.get("severity", "warning"),
        "status": alert.get("status", "firing"),
        "instance": labels.get("instance", ""),
        "tlp": DEFAULT_TLP,
        "starts_at": alert.get("startsAt"),
    }

    if ends_at is not None:
        properties["ends_at"] = ends_at

    return {
        "label": "MonitoringAlert",
        "properties": properties,
    }


def _verify_secret(request: Request) -> bool:
    """Verify the shared-secret Authorization header if configured."""
    if not WEBHOOK_SECRET:
        return True  # No secret configured — allow all.
    auth = request.headers.get("Authorization", "")
    expected = f"Bearer {WEBHOOK_SECRET}"
    return hmac.compare_digest(auth, expected)


def _build_app(js_holder: dict[str, Any]) -> Starlette:
    """Build the Starlette app with the webhook endpoint."""

    async def webhook(request: Request) -> JSONResponse:
        """Handle AlertManager webhook POST."""
        if not _verify_secret(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)

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
                published += 1

        logger.info(
            "Webhook received %d alerts, published %d entities",
            len(alerts),
            published,
        )
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
            name="ENRICHED",
            subjects=["enriched.entity.>"],
            retention="work_queue",
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
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    asyncio.run(run())
