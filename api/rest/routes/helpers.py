"""api.rest.routes.helpers — Shared utilities for REST route handlers."""

from __future__ import annotations

from fastapi import Request


def caller_from_request(request: Request) -> dict:
    """Build caller_identity dict from request state or fallback headers."""
    identity = getattr(request.state, "identity", None)
    if identity is not None:
        return {
            "max_tlp": identity.max_tlp,
            "actor": identity.sub,
            "allowed_compartments": identity.allowed_compartments,
        }
    from api.config import DEFAULT_TLP

    tlp = int(request.headers.get("X-CG-TLP", "0") or "0")
    return {
        "max_tlp": tlp or DEFAULT_TLP,
        "actor": "rest_api",
        "allowed_compartments": [],
    }
