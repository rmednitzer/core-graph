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
