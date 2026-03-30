"""api.authz.cerbos — Cerbos ABAC client.

Wraps the Cerbos SDK for attribute-based access control. Evaluates
policies defined in ``policies/`` against the CallerIdentity from OIDC.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from api import config
from api.rest.middleware.oidc import CallerIdentity

logger = logging.getLogger(__name__)

_http_client: httpx.AsyncClient | None = None


def _get_http_client() -> httpx.AsyncClient:
    """Return a shared httpx client for Cerbos API calls."""
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(
            base_url=config.CERBOS_ENDPOINT,
            timeout=5,
        )
    return _http_client


async def check_resource(
    principal: CallerIdentity,
    resource_type: str,
    resource_id: str,
    action: str,
    resource_attrs: dict[str, Any] | None = None,
) -> bool:
    """Check if a principal is allowed to perform an action on a resource.

    Returns False (deny) on any error (fail closed).
    """
    payload = {
        "principal": {
            "id": principal.sub,
            "roles": principal.roles,
            "attr": {
                "max_tlp": principal.max_tlp,
                "groups": principal.groups,
                "department": principal.department,
                "allowed_compartments": principal.allowed_compartments,
            },
        },
        "resource": {
            "kind": resource_type,
            "id": resource_id,
            "attr": resource_attrs or {},
        },
        "actions": [action],
    }

    try:
        client = _get_http_client()
        resp = await client.post(
            "/api/check/resources",
            json={"requestId": resource_id, "includeMeta": False, **payload},
        )
        resp.raise_for_status()
        result = resp.json()

        # Parse Cerbos response
        results = result.get("results", [])
        if results:
            actions = results[0].get("actions", {})
            return actions.get(action, "EFFECT_DENY") == "EFFECT_ALLOW"
        return False
    except Exception:
        logger.exception("Cerbos check_resource failed, denying by default")
        return False


async def plan_resources(
    principal: CallerIdentity,
    resource_type: str,
    action: str,
) -> dict[str, Any]:
    """Request a query plan from Cerbos for RLS integration.

    Returns a dict with query plan information that can be used to
    construct SQL WHERE clause fragments for server-side filtering.
    Returns empty dict on error (fail closed = no access).
    """
    payload = {
        "principal": {
            "id": principal.sub,
            "roles": principal.roles,
            "attr": {
                "max_tlp": principal.max_tlp,
                "groups": principal.groups,
                "department": principal.department,
            },
        },
        "resource": {
            "kind": resource_type,
        },
        "action": action,
    }

    try:
        client = _get_http_client()
        resp = await client.post(
            "/api/plan/resources",
            json={"requestId": "plan", **payload},
        )
        resp.raise_for_status()
        return resp.json()
    except Exception:
        logger.exception("Cerbos plan_resources failed, returning empty plan")
        return {}
