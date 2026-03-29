"""ingest.connectors.keycloak.adapter — Keycloak Admin API adapter.

Polls the Keycloak Admin REST API for users, groups, roles, and
role mappings. Publishes IAM entities and relationships to NATS
for graph writer consumption. Extends AdapterBase.

All IAM entities are published with TLP >= 2 (AMBER floor).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import httpx

from ingest.canonical import canonical_key
from ingest.connectors.base import AdapterBase, AdapterConfig
from ingest.connectors.keycloak.config import KeycloakConfig

logger = logging.getLogger(__name__)

ENTITY_SUBJECT = "enriched.entity.iam.keycloak"
RELATIONSHIP_SUBJECT = "enriched.relationship.iam.keycloak"
IAM_TLP_FLOOR = 2  # TLP:AMBER — never publish IAM data below this


class KeycloakAdapter(AdapterBase):
    """Keycloak Admin API adapter using AdapterBase."""

    def __init__(self, config: KeycloakConfig | None = None) -> None:
        self.kc_config = config or KeycloakConfig()
        super().__init__(
            AdapterConfig(
                name="keycloak",
                nats_subject=ENTITY_SUBJECT,
                nats_stream="ENRICHED",
                poll_interval=self.kc_config.interval,
                default_tlp=IAM_TLP_FLOOR,
                delta_sync=True,
            )
        )
        self._http_client: httpx.AsyncClient | None = None
        self._access_token: str | None = None
        self._token_expires_at: float = 0.0
        self._relationships: list[dict[str, Any]] = []

    async def _acquire_token(self) -> str:
        """Acquire or refresh an admin API access token."""
        if self._access_token and time.time() < self._token_expires_at:
            return self._access_token

        if self._http_client is None:
            raise RuntimeError("HTTP client not initialised")

        token_url = (
            f"{self.kc_config.url.rstrip('/')}/realms/{self.kc_config.realm}"
            f"/protocol/openid-connect/token"
        )
        data = {
            "grant_type": "client_credentials",
            "client_id": self.kc_config.client_id,
            "client_secret": self.kc_config.client_secret,
        }

        resp = await self._http_client.post(token_url, data=data, timeout=10)
        resp.raise_for_status()
        body = resp.json()

        self._access_token = body["access_token"]
        expires_in = body.get("expires_in", 300)
        # Refresh at 80% of expiry
        self._token_expires_at = time.time() + (expires_in * 0.8)

        self._logger.info("Keycloak token acquired, expires_in=%ds", expires_in)
        return self._access_token

    async def _admin_get(self, path: str) -> list[dict[str, Any]]:
        """GET from the Keycloak Admin API with auto-refresh."""
        if self._http_client is None:
            return []

        token = await self._acquire_token()
        url = f"{self.kc_config.url.rstrip('/')}/admin/realms/{self.kc_config.realm}{path}"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

        results: list[dict[str, Any]] = []
        first = 0
        page_size = 100

        while True:
            resp = await self._http_client.get(
                url,
                params={"first": first, "max": page_size},
                headers=headers,
                timeout=30,
            )
            resp.raise_for_status()
            page = resp.json()
            if not isinstance(page, list):
                page = [page]
            results.extend(page)
            if len(page) < page_size:
                break
            first += page_size

        return results

    async def fetch(self, since: str | None) -> list[dict[str, Any]]:
        """Fetch users, groups, and roles from Keycloak."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                verify=self.kc_config.verify_ssl
            )

        self._relationships = []
        all_entities: list[dict[str, Any]] = []

        # Fetch users
        users = await self._admin_get("/users")
        for user in users:
            user["_kc_type"] = "user"
            all_entities.append(user)

            # Fetch user role mappings
            user_id = user["id"]
            role_mappings = await self._admin_get(
                f"/users/{user_id}/role-mappings/realm/composite"
            )
            for role in role_mappings:
                self._relationships.append({
                    "type": "has_role",
                    "principal_key": canonical_key("principal", user_id),
                    "role_key": canonical_key("role", f"{self.kc_config.realm}:{role['name']}"),
                    "source": "keycloak",
                })

            # Fetch user group memberships
            groups = await self._admin_get(f"/users/{user_id}/groups")
            for group in groups:
                self._relationships.append({
                    "type": "member_of",
                    "principal_key": canonical_key("principal", user_id),
                    "group_key": canonical_key("group", group["id"]),
                    "source": "keycloak",
                })

        # Fetch groups
        groups = await self._admin_get("/groups")
        for group in self._flatten_groups(groups):
            group["_kc_type"] = "group"
            all_entities.append(group)

        # Fetch realm roles
        roles = await self._admin_get("/roles")
        for role in roles:
            role["_kc_type"] = "role"
            all_entities.append(role)

        return all_entities

    def _flatten_groups(
        self, groups: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Flatten nested groups into a flat list, recording member_of edges."""
        flat: list[dict[str, Any]] = []
        for group in groups:
            flat.append(group)
            subgroups = group.get("subGroups", [])
            for sub in subgroups:
                # Record nested group membership
                self._relationships.append({
                    "type": "member_of",
                    "principal_key": canonical_key("group", sub["id"]),
                    "group_key": canonical_key("group", group["id"]),
                    "source": "keycloak",
                })
            flat.extend(self._flatten_groups(subgroups))
        return flat

    def map(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        """Map a Keycloak entity to a graph vertex payload."""
        kc_type = raw.get("_kc_type", "")

        if kc_type == "user":
            return self._map_user(raw)
        elif kc_type == "group":
            return self._map_group(raw)
        elif kc_type == "role":
            return self._map_role(raw)
        return None

    def _map_user(self, user: dict[str, Any]) -> dict[str, Any]:
        """Map a Keycloak user to a Principal vertex."""
        created_ms = user.get("createdTimestamp", 0)
        return {
            "label": "Principal",
            "properties": {
                "canonical_key": canonical_key("principal", user["id"]),
                "principal_id": user["id"],
                "username": user.get("username", ""),
                "email": user.get("email", ""),
                "enabled": user.get("enabled", False),
                "created_at": _ms_to_iso(created_ms),
                "last_login": _ms_to_iso(user.get("lastLogin")),
                "source": "keycloak",
                "tlp": max(IAM_TLP_FLOOR, IAM_TLP_FLOOR),  # Enforce floor
            },
        }

    def _map_group(self, group: dict[str, Any]) -> dict[str, Any]:
        """Map a Keycloak group to a Group vertex."""
        return {
            "label": "Group",
            "properties": {
                "canonical_key": canonical_key("group", group["id"]),
                "group_id": group["id"],
                "name": group.get("name", ""),
                "path": group.get("path", ""),
                "source": "keycloak",
                "tlp": max(IAM_TLP_FLOOR, IAM_TLP_FLOOR),
            },
        }

    def _map_role(self, role: dict[str, Any]) -> dict[str, Any]:
        """Map a Keycloak role to a Role vertex."""
        return {
            "label": "Role",
            "properties": {
                "canonical_key": canonical_key(
                    "role", f"{self.kc_config.realm}:{role['name']}"
                ),
                "role_name": role["name"],
                "realm": self.kc_config.realm,
                "client_id": role.get("containerId", ""),
                "source": "keycloak",
                "tlp": max(IAM_TLP_FLOOR, IAM_TLP_FLOOR),
            },
        }

    async def run(
        self,
        nats_url: str | None = None,
        valkey_url: str | None = None,
        pg_dsn: str | None = None,
    ) -> None:
        """Override run to also publish relationship payloads after entities."""
        if not self.kc_config.client_secret:
            self._logger.warning(
                "Keycloak client_secret is empty, adapter disabled"
            )
            return

        # Store original _publish
        original_publish = self._publish

        # Publish collected relationships after all entities
        async def _publish_with_relationships(entity: dict[str, Any]) -> None:
            await original_publish(entity)

        self._publish = _publish_with_relationships  # type: ignore[assignment]

        try:
            # Use a modified loop that publishes relationships after each cycle
            await self._run_with_relationships(nats_url, valkey_url, pg_dsn)
        finally:
            if self._http_client:
                await self._http_client.aclose()

    async def _run_with_relationships(
        self,
        nats_url: str | None,
        valkey_url: str | None,
        pg_dsn: str | None,
    ) -> None:
        """Run the adapter with relationship publishing."""
        import nats as nats_lib
        import redis.asyncio as redis_mod

        from api.config import NATS_URL as default_nats
        from api.config import PG_DSN as default_pg
        from api.config import VALKEY_URL as default_valkey
        from ingest.metrics import adapter_entities_total, adapter_fetch_total

        nats_addr = nats_url or default_nats
        valkey_addr = valkey_url or default_valkey
        dsn = pg_dsn or default_pg

        self._nc = await nats_lib.connect(nats_addr)
        self._js = self._nc.jetstream()
        self._cache = redis_mod.from_url(valkey_addr)

        await self._ensure_stream()

        self._logger.info(
            "Keycloak adapter started, realm=%s, interval=%ds",
            self.kc_config.realm,
            self.config.poll_interval,
        )

        try:
            while True:
                since = (
                    await self._get_cached_timestamp()
                    if self.config.delta_sync
                    else None
                )
                try:
                    raw_objects = await self.fetch(since)
                    adapter_fetch_total.labels(
                        adapter=self.config.name, status="success"
                    ).inc()
                except Exception:
                    adapter_fetch_total.labels(
                        adapter=self.config.name, status="error"
                    ).inc()
                    self._logger.exception("Fetch failed")
                    await asyncio.sleep(self.config.poll_interval or 60)
                    continue

                count = 0
                for raw in raw_objects:
                    entity = self.map(raw)
                    if entity is None:
                        continue
                    try:
                        if self._js:
                            await self._js.publish(
                                ENTITY_SUBJECT,
                                json.dumps(entity, default=str).encode(),
                            )
                        label = entity.get("label", "unknown")
                        adapter_entities_total.labels(
                            adapter=self.config.name, label=label
                        ).inc()
                        count += 1
                    except Exception:
                        self._logger.warning("Entity publish failed", exc_info=True)

                # Publish relationships
                rel_count = 0
                for rel in self._relationships:
                    try:
                        if self._js:
                            await self._js.publish(
                                RELATIONSHIP_SUBJECT,
                                json.dumps(rel, default=str).encode(),
                            )
                        rel_count += 1
                    except Exception:
                        self._logger.warning("Relationship publish failed", exc_info=True)

                if count > 0:
                    await self._cache_timestamp()
                    await self._audit(count, dsn)

                self._logger.info(
                    "Keycloak sync: entities=%d relationships=%d",
                    count,
                    rel_count,
                )

                if self.config.poll_interval <= 0:
                    break
                await asyncio.sleep(self.config.poll_interval)
        finally:
            if self._cache:
                await self._cache.aclose()
            if self._nc:
                await self._nc.close()


def _ms_to_iso(ms: int | None) -> str:
    """Convert millisecond timestamp to ISO 8601 string."""
    if ms is None or ms == 0:
        return ""
    from datetime import UTC, datetime

    return datetime.fromtimestamp(ms / 1000, tz=UTC).isoformat()


async def run(
    config: KeycloakConfig | None = None,
    nats_url: str | None = None,
    valkey_url: str | None = None,
    pg_dsn: str | None = None,
) -> None:
    """Entry point for the Keycloak adapter."""
    adapter = KeycloakAdapter(config)
    await adapter.run(nats_url, valkey_url, pg_dsn)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    asyncio.run(run())
