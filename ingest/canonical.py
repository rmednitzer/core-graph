"""ingest.canonical — deterministic entity key generation.

Produces a stable, content-addressable key for each IOC so that the same
indicator arriving from different satellite sources (Wazuh, MISP, OpenCTI,
OSINT feeds) maps to a single graph vertex.
"""

from __future__ import annotations

import hashlib


def canonical_key(ioc_type: str, value: str) -> str:
    """Return a deterministic hex digest for *ioc_type* + *value*.

    Normalisation rules applied before hashing:
    * leading / trailing whitespace is stripped
    * the value is lowercased
    """
    normalised = f"{ioc_type.strip().lower()}:{value.strip().lower()}"
    return hashlib.sha256(normalised.encode()).hexdigest()
