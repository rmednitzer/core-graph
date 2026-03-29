"""api.rest.middleware.oidc — OIDC JWT validation middleware.

Validates JWT tokens from an OIDC-compliant IdP. When CG_OIDC_ENABLED is
false (default for local dev), falls back to the existing X-CG-TLP header
behaviour with a synthetic CallerIdentity.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
import jwt
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from api import config

logger = logging.getLogger(__name__)


class CallerIdentity(BaseModel):
    """Authenticated caller context attached to every request."""

    sub: str
    roles: list[str]
    max_tlp: int
    groups: list[str] = []
    department: str = ""
    allowed_compartments: list[str] = []


class _JWKSCache:
    """Simple JWKS cache backed by Valkey."""

    _CACHE_KEY = "cg:oidc:jwks"

    def __init__(self) -> None:
        self._jwks_client: jwt.PyJWKClient | None = None

    async def get_signing_key(self, token: str) -> jwt.PyJWK:
        """Return the signing key for the given token, using cached JWKS."""
        if self._jwks_client is None:
            discovery_url = config.OIDC_ISSUER_URL.rstrip("/") + "/.well-known/openid-configuration"
            async with httpx.AsyncClient() as client:
                resp = await client.get(discovery_url, timeout=10)
                resp.raise_for_status()
                oidc_config = resp.json()
            jwks_uri = oidc_config["jwks_uri"]
            self._jwks_client = jwt.PyJWKClient(
                jwks_uri,
                cache_keys=True,
                lifespan=config.OIDC_JWKS_CACHE_TTL,
            )
        return self._jwks_client.get_signing_key_from_jwt(token)

    def clear(self) -> None:
        """Clear cached JWKS client (forces re-fetch on next call)."""
        self._jwks_client = None


_jwks_cache = _JWKSCache()


def _build_dev_identity(request: Request) -> CallerIdentity:
    """Build a synthetic CallerIdentity from X-CG-TLP header (dev mode)."""
    tlp = int(request.headers.get("X-CG-TLP", "0") or "0")
    return CallerIdentity(
        sub="dev-user",
        roles=["admin"],
        max_tlp=tlp or config.DEFAULT_TLP,
        groups=[],
        department="development",
        allowed_compartments=[],
    )


class OIDCMiddleware(BaseHTTPMiddleware):
    """Validate OIDC JWT tokens and attach CallerIdentity to request state.

    When ``CG_OIDC_ENABLED`` is false, injects a synthetic dev identity
    derived from the ``X-CG-TLP`` header.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Skip auth for health endpoints
        if request.url.path in ("/healthz", "/readyz", "/metrics"):
            request.state.identity = _build_dev_identity(request)
            return await call_next(request)

        if not config.OIDC_ENABLED:
            request.state.identity = _build_dev_identity(request)
            return await call_next(request)

        # Extract bearer token
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid Authorization header"},
            )
        token = auth_header[7:]

        try:
            signing_key = await _jwks_cache.get_signing_key(token)
            payload: dict[str, Any] = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                audience=config.OIDC_AUDIENCE,
                issuer=config.OIDC_ISSUER_URL,
                options={"require": ["exp", "iss", "sub", "aud"]},
            )
        except jwt.ExpiredSignatureError:
            return JSONResponse(
                status_code=401,
                content={"detail": "Token expired"},
            )
        except jwt.InvalidTokenError as exc:
            logger.warning("OIDC token validation failed: %s", exc)
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid token"},
            )
        except Exception:
            logger.exception("OIDC JWKS fetch or token validation error")
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication error"},
            )

        # Build CallerIdentity from JWT claims
        identity = CallerIdentity(
            sub=payload.get("sub", ""),
            roles=payload.get("roles", []),
            max_tlp=int(payload.get("tlp_clearance", config.DEFAULT_TLP)),
            groups=payload.get("groups", []),
            department=payload.get("department", ""),
            allowed_compartments=payload.get("allowed_compartments", []),
        )
        request.state.identity = identity

        return await call_next(request)
