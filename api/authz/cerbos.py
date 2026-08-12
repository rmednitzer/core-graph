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


def principal_from_caller(caller_identity: dict[str, Any] | None) -> dict[str, Any]:
    """Build a Cerbos principal from an MCP tool's ``caller_identity`` dict.

    The counterpart to :func:`check_resource`, which takes the REST layer's
    typed ``CallerIdentity``. MCP tools receive a plain dict instead, and were
    each assembling this shape by hand.

    A caller with no ``roles`` produces a principal with none, which every
    resource policy denies. That is the intended reading: authorization is
    decided by role, so a caller that presents no role has not established one.
    """
    caller = caller_identity or {}
    return {
        "id": caller.get("actor", "unknown"),
        "roles": caller.get("roles", []),
        "attr": caller.get("attr", {}),
    }


async def require_caller_action(
    caller_identity: dict[str, Any] | None,
    resource_kind: str,
    resource_id: str,
    action: str,
    resource_attrs: dict[str, Any] | None = None,
) -> None:
    """Raise ``PermissionError`` unless Cerbos allows the action.

    The raising form exists because the alternative -- returning a bool and
    letting each call site decide -- is one forgotten ``if`` away from a tool
    that checks authorization and then proceeds regardless. Four call sites in
    the memory tools use this; a fifth (identity attribution) predates it and
    keeps its own message.

    Fail closed by construction: :func:`check_action` returns ``False`` on any
    transport error or non-allow effect, so an unreachable Cerbos denies rather
    than admits.
    """
    allowed = await check_action(
        principal_from_caller(caller_identity),
        resource_kind=resource_kind,
        resource_id=resource_id,
        action=action,
        resource_attrs=resource_attrs,
    )
    if not allowed:
        roles = (caller_identity or {}).get("roles") or []
        raise PermissionError(
            f"Denied by Cerbos policy: {action} on {resource_kind}. "
            f"Caller roles: {sorted(roles) if roles else 'none presented'}."
        )


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
