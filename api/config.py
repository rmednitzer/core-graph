"""api.config — Shared configuration for core-graph services.

All configuration is sourced from environment variables with sensible
development defaults. Production deployments override via env or secrets.
"""

from __future__ import annotations

import os

PG_DSN = os.environ.get(
    "CG_PG_DSN",
    "postgresql://cg_admin:cg_dev_only@localhost:5432/core_graph",
)

# The DSN the serving pool in api.db connects with. Separate from PG_DSN
# because the two have different privilege requirements, not because they
# point at different databases.
#
# PG_DSN is the owner identity: it runs migrations, and it is what the trusted
# writers (ingest/graph_writer.py, the DLQ processor, the connectors) and the
# evidence tooling use. Those write at whatever TLP their source declares and
# must not be filtered by a caller's clearance.
#
# PG_APP_DSN is the request-serving identity, cg_app (migration 038):
# NOSUPERUSER NOBYPASSRLS, so the policies from 004, 010, 022, 028 and 037 are
# actually evaluated for it. Superusers bypass row-level security
# unconditionally, which is why pointing the pool at the owner meant no policy
# in this repository was ever enforced. See ADR-0014.
#
# Falls back to PG_DSN when unset, so an image deployed against a schema that
# predates migration 038 still starts rather than failing to connect to a role
# that does not exist yet. That fallback silently restores the unenforced
# posture, so api.db logs the role it actually connected as at pool open, and
# warns when that role bypasses RLS.
PG_APP_DSN = os.environ.get("CG_PG_APP_DSN", "") or PG_DSN
NATS_URL = os.environ.get("CG_NATS_URL", "nats://localhost:4222")
VALKEY_URL = os.environ.get("CG_VALKEY_URL", "redis://localhost:6379")
DEFAULT_TLP = int(os.environ.get("CG_DEFAULT_TLP", "2"))

# OIDC authentication.
#
# OIDC_ENABLED defaults to true (fail-closed). A misconfigured deployment
# that forgets to set CG_OIDC_ISSUER_URL will return 401 on every request,
# not silently fall back to a synthetic admin identity.
#
# DEV_MODE is the explicit opt-in for the synthetic dev identity (admin
# role, max_tlp from X-CG-TLP header). It is only consulted when
# OIDC_ENABLED is false. Without DEV_MODE the OIDC middleware refuses
# requests with 503, surfacing the misconfiguration immediately instead
# of opening the door.
OIDC_ENABLED = os.environ.get("CG_OIDC_ENABLED", "true").lower() == "true"
OIDC_ISSUER_URL = os.environ.get("CG_OIDC_ISSUER_URL", "")
OIDC_AUDIENCE = os.environ.get("CG_OIDC_AUDIENCE", "core-graph")
OIDC_JWKS_CACHE_TTL = int(os.environ.get("CG_OIDC_JWKS_CACHE_TTL", "3600"))
DEV_MODE = os.environ.get("CG_DEV_MODE", "false").lower() == "true"

# SpiceDB (ReBAC)
SPICEDB_ENDPOINT = os.environ.get("CG_SPICEDB_ENDPOINT", "localhost:50051")
SPICEDB_TOKEN = os.environ.get("CG_SPICEDB_TOKEN", "")

# Cerbos (ABAC)
# 3592, not 3593. Cerbos listens for HTTP on 3592 and gRPC on 3593 (its own SDK
# states both: cerbos.sdk.container.HTTP_PORT / GRPC_PORT). api.authz.cerbos is
# an HTTP client, so the previous default pointed it at the gRPC listener and
# every check failed with httpx "illegal request line" -- which check_action
# then turned into a fail-closed deny.
#
# That made every Cerbos decision in this repository a denial, silently, since
# the client was written. It stayed invisible because nothing on a CI-exercised
# path called Cerbos: identity_attribution needs the ciso role and has no
# integration test. Wiring the memory tools (ADR-0018) put a Cerbos call on a
# path the integration suite runs, and it failed immediately.
CERBOS_ENDPOINT = os.environ.get("CG_CERBOS_ENDPOINT", "http://localhost:3592")

# MinIO (evidence store)
MINIO_ENDPOINT = os.environ.get("CG_MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.environ.get("CG_MINIO_ACCESS_KEY", "cg_admin")
MINIO_SECRET_KEY = os.environ.get("CG_MINIO_SECRET_KEY", "cg_dev_only_minio")
MINIO_EVIDENCE_BUCKET = os.environ.get("CG_MINIO_EVIDENCE_BUCKET", "evidence")
MINIO_USE_SSL = os.environ.get("CG_MINIO_USE_SSL", "false").lower() == "true"

# Connection pool
PG_POOL_MIN = int(os.environ.get("CG_PG_POOL_MIN", "2"))
PG_POOL_MAX = int(os.environ.get("CG_PG_POOL_MAX", "10"))

# Netbox (CMDB/IPAM)
NETBOX_URL = os.environ.get("NETBOX_URL", "http://localhost:8080")
NETBOX_TOKEN = os.environ.get("NETBOX_TOKEN", "")

# Prometheus AlertManager webhook
PROMETHEUS_WEBHOOK_HOST = os.environ.get("CG_PROMETHEUS_WEBHOOK_HOST", "0.0.0.0")
PROMETHEUS_WEBHOOK_PORT = int(os.environ.get("CG_PROMETHEUS_WEBHOOK_PORT", "9095"))

# Embedding model
EMBEDDING_PROVIDER = os.environ.get("CG_EMBEDDING_PROVIDER", "none")
EMBEDDING_MODEL = os.environ.get("CG_EMBEDDING_MODEL", "nomic-embed-text")
EMBEDDING_URL = os.environ.get("CG_EMBEDDING_URL", "http://localhost:11434")
EMBEDDING_DIMENSIONS = int(os.environ.get("CG_EMBEDDING_DIMENSIONS", "768"))

# RFC 3161 Timestamping
TSA_URL = os.environ.get("CG_TSA_URL", "https://freetsa.org/tsr")
TSA_ENABLED = os.environ.get("CG_TSA_ENABLED", "false").lower() == "true"
# Optional path to the TSA's CA certificate. When set, timestamp tokens are
# verified to chain to this CA before they are persisted (fail-closed).
TSA_CERT_PATH = os.environ.get("CG_TSA_CERT_PATH", "") or None

# Keycloak (IAM)
KEYCLOAK_URL = os.environ.get("CG_KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_REALM = os.environ.get("CG_KEYCLOAK_REALM", "master")
KEYCLOAK_CLIENT_ID = os.environ.get("CG_KEYCLOAK_CLIENT_ID", "admin-cli")
KEYCLOAK_CLIENT_SECRET = os.environ.get("CG_KEYCLOAK_CLIENT_SECRET", "")

# AI memory (Layer 5) — salience formula constants.
# salience = recency_weight * exp(-decay * age_seconds)
#          + access_weight  * log(1 + access_count)
#          + relevance_weight * cosine_sim_to_session_anchor
# Defaults: 1-day half-life on recency, modest access boost, 30% weight on relevance.
SALIENCE_RECENCY_WEIGHT = float(os.environ.get("CG_SALIENCE_RECENCY_WEIGHT", "0.5"))
SALIENCE_ACCESS_WEIGHT = float(os.environ.get("CG_SALIENCE_ACCESS_WEIGHT", "0.2"))
SALIENCE_RELEVANCE_WEIGHT = float(os.environ.get("CG_SALIENCE_RELEVANCE_WEIGHT", "0.3"))
SALIENCE_DECAY = float(os.environ.get("CG_SALIENCE_DECAY", str(1.0 / 86400.0)))
