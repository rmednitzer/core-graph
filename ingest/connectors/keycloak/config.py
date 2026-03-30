"""ingest.connectors.keycloak.config — Configuration for the Keycloak adapter."""

from __future__ import annotations

import os

from pydantic import BaseModel


class KeycloakConfig(BaseModel):
    """Configuration for the Keycloak Admin API adapter."""

    url: str = os.environ.get("CG_KEYCLOAK_URL", "http://localhost:8080")
    realm: str = os.environ.get("CG_KEYCLOAK_REALM", "master")
    client_id: str = os.environ.get("CG_KEYCLOAK_CLIENT_ID", "admin-cli")
    client_secret: str = os.environ.get("CG_KEYCLOAK_CLIENT_SECRET", "")
    interval: int = 300  # Poll interval in seconds
    verify_ssl: bool = True
