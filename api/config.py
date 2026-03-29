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
NATS_URL = os.environ.get("CG_NATS_URL", "nats://localhost:4222")
VALKEY_URL = os.environ.get("CG_VALKEY_URL", "redis://localhost:6379")
DEFAULT_TLP = int(os.environ.get("CG_DEFAULT_TLP", "2"))

# OIDC authentication
OIDC_ENABLED = os.environ.get("CG_OIDC_ENABLED", "false").lower() == "true"
OIDC_ISSUER_URL = os.environ.get("CG_OIDC_ISSUER_URL", "")
OIDC_AUDIENCE = os.environ.get("CG_OIDC_AUDIENCE", "core-graph")
OIDC_JWKS_CACHE_TTL = int(os.environ.get("CG_OIDC_JWKS_CACHE_TTL", "3600"))

# SpiceDB (ReBAC)
SPICEDB_ENDPOINT = os.environ.get("CG_SPICEDB_ENDPOINT", "localhost:50051")
SPICEDB_TOKEN = os.environ.get("CG_SPICEDB_TOKEN", "")

# Cerbos (ABAC)
CERBOS_ENDPOINT = os.environ.get("CG_CERBOS_ENDPOINT", "http://localhost:3593")

# MinIO (evidence store)
MINIO_ENDPOINT = os.environ.get("CG_MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.environ.get("CG_MINIO_ACCESS_KEY", "cg_admin")
MINIO_SECRET_KEY = os.environ.get("CG_MINIO_SECRET_KEY", "cg_dev_only_minio")
MINIO_EVIDENCE_BUCKET = os.environ.get("CG_MINIO_EVIDENCE_BUCKET", "evidence")
MINIO_USE_SSL = os.environ.get("CG_MINIO_USE_SSL", "false").lower() == "true"

# Connection pool
PG_POOL_MIN = int(os.environ.get("CG_PG_POOL_MIN", "2"))
PG_POOL_MAX = int(os.environ.get("CG_PG_POOL_MAX", "10"))
