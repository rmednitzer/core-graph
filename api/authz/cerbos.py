"""api.authz.cerbos — Cerbos ABAC client.

Wraps the Cerbos SDK for attribute-based access control. Evaluates
policies defined in ``policies/`` against the CallerIdentity from OIDC.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import httpx

from api import config

if TYPE_CHECKING:
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


async def check_action(
    principal: dict[str, Any],
    resource_kind: str,
    resource_id: str,
    action: str,
    resource_attrs: dict[str, Any] | None = None,
) -> bool:
    """Evaluate one ``(principal, resource, action)`` triple against Cerbos.

    Posts to ``/api/check/resources`` using the documented batch request body
    (``resources: [{resource, actions}]``) and reads the **string** effect from
    ``results[0].actions[action]``. Cerbos serialises each action's decision as
    the enum string ``"EFFECT_ALLOW"`` / ``"EFFECT_DENY"`` -- not a nested
    object with an ``effect`` field -- so the value is compared directly.

    ``principal`` is the Cerbos principal object (``id``, ``roles``, ``attr``).

    Fail closed: any transport error, an empty result set, or any effect other
    than ``EFFECT_ALLOW`` returns ``False``.
    """
    payload = {
        "requestId": resource_id or "check",
        "principal": principal,
        "resources": [
            {
                "resource": {
                    "kind": resource_kind,
                    "id": resource_id,
                    "attr": resource_attrs or {},
                },
                "actions": [action],
            }
        ],
    }
    try:
        client = _get_http_client()
        resp = await client.post("/api/check/resources", json=payload)
        resp.raise_for_status()
        results = resp.json().get("results", [])
        if not results:
            logger.warning(
                "Empty Cerbos response for %s/%s, denying by default",
                resource_kind,
                action,
            )
            return False
        return results[0].get("actions", {}).get(action) == "EFFECT_ALLOW"
    except Exception:
        logger.exception(
            "Cerbos check failed for %s/%s, denying by default",
            resource_kind,
            action,
        )
        return False


async def check_resource(
    principal: CallerIdentity,
    resource_type: str,
    resource_id: str,
    action: str,
    resource_attrs: dict[str, Any] | None = None,
) -> bool:
    """Check if a principal is allowed to perform an action on a resource.

    Builds the Cerbos principal from the OIDC-attested ``CallerIdentity`` and
    delegates to :func:`check_action`. Returns ``False`` (deny) on any error
    (fail closed).
    """
    cerbos_principal = {
        "id": principal.sub,
        "roles": principal.roles,
        "attr": {
            "max_tlp": principal.max_tlp,
            "groups": principal.groups,
            "department": principal.department,
            "allowed_compartments": principal.allowed_compartments,
        },
    }
    return await check_action(cerbos_principal, resource_type, resource_id, action, resource_attrs)


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
