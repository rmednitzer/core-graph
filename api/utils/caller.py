"""api.utils.caller — Caller identity extraction shared by REST and TAXII layers."""

from __future__ import annotations

from typing import Any

from fastapi import Request

from api.config import DEFAULT_TLP


def caller_from_request(
    request: Request,
    *,
    fallback_actor: str = "rest_api",
    honor_tlp_header: bool = True,
) -> dict[str, Any]:
    """Build a ``caller_identity`` dict from ``request.state.identity``.

    When the OIDC middleware has not attached an identity, fall back to
    a synthetic dict using ``fallback_actor`` and (optionally) the
    ``X-CG-TLP`` development header.
    """
    identity = getattr(request.state, "identity", None)
    if identity is not None:
        return {
            "max_tlp": identity.max_tlp,
            "actor": identity.sub,
            "allowed_compartments": identity.allowed_compartments,
        }

    tlp = 0
    if honor_tlp_header:
        tlp = int(request.headers.get("X-CG-TLP", "0") or "0")

    return {
        "max_tlp": tlp or DEFAULT_TLP,
        "actor": fallback_actor,
        "allowed_compartments": [],
    }
