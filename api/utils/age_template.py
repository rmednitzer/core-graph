"""api.utils.age_template — Safe Cypher template construction.

AGE openCypher cannot bind labels or relationship types as parameters.
Any value used as a label, edge type, or property *key* must be
validated against an allowlist before interpolation. This module
provides the allowlist registry and the interpolation helper.

Allowlists are initialised from built-in static sets covering every
label produced by the migration files in `schema/migrations/`. They may
be extended at runtime via `register_vertex_labels()` and
`register_edge_labels()` when new labels are introduced (e.g. by a
follow-up migration's startup hook). Skills that accept user-supplied
labels must validate them against the appropriate allowlist before
interpolation.

This complements `api.utils.cypher_safety.validate_label` which does
character-set validation only.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

from api.utils.cypher_safety import validate_label

logger = logging.getLogger(__name__)

# Static allowlists. These are extended at runtime by `register_*`
# helpers when new labels are introduced via migrations.
_ALLOWED_VERTEX_LABELS: set[str] = {
    # Layer 1: threat intel
    "ThreatActor",
    "Indicator",
    "Vulnerability",
    "AttackPattern",
    "Campaign",
    "Malware",
    "IntrusionSet",
    "Identity",
    "Location",
    "Report",
    "Infrastructure",
    "CourseOfAction",
    # Layer 2: security events / OCSF
    "SecurityEvent",
    "Alert",
    "Incident",
    # Layer 3: OSINT
    "OSINTArtifact",
    "Source",
    # Layer 4: compliance
    "ComplianceControl",
    "ComplianceDomain",
    "EvidenceRecord",
    # Layer 5: AI memory
    "Session",
    "Episode",
    "ExtractedFact",
    "ConceptEntity",
    # Layer 6: forensic timeline
    "TimelineEvent",
    "Artifact",
    # Layer 7: infrastructure
    "Host",
    "Network",
    "Site",
    "Interface",
    "Service",
    "MonitoringAlert",
    "CanonicalIP",
    "CanonicalDomain",
    # Layer 8: IAM
    "Principal",
    "Group",
    "Role",
    "Permission",
    "AccessPolicy",
}

_ALLOWED_EDGE_LABELS: set[str] = {
    # Generic graph
    "related",
    "observed_as",
    "indicates",
    "mitigates",
    # Layer 1 / 2 / 3
    "uses",
    "targets",
    "attributed_to",
    "communicates_with",
    "observed_on",
    "indicates_attack",
    # Layer 4
    "satisfies",
    "evidenced_by",
    # Layer 5: AI memory
    "belongs_to",
    "extracted_from",
    "mentions",
    "supersedes",
    # Layer 7
    "hosts",
    "connected_to",
    "located_at",
    "runs",
    # Layer 8
    "has_role",
    "member_of",
    "grants",
    "actor_in",
    "manages",
    "owns",
    "same_as",
}


def register_vertex_labels(labels: Iterable[str]) -> None:
    """Add labels to the allowlist after migration-time registration."""
    for label in labels:
        validate_label(label)
        _ALLOWED_VERTEX_LABELS.add(label)


def register_edge_labels(labels: Iterable[str]) -> None:
    for label in labels:
        validate_label(label)
        _ALLOWED_EDGE_LABELS.add(label)


def validate_vertex_label(label: str) -> str:
    """Return label iff it passes character validation AND is in the allowlist."""
    validate_label(label)
    if label not in _ALLOWED_VERTEX_LABELS:
        raise ValueError(
            f"Vertex label {label!r} not in allowlist. Register via "
            "api.utils.age_template.register_vertex_labels()."
        )
    return label


def validate_edge_label(label: str) -> str:
    """Return edge label iff it passes character validation AND is in the allowlist."""
    validate_label(label)
    if label not in _ALLOWED_EDGE_LABELS:
        raise ValueError(
            f"Edge label {label!r} not in allowlist. Register via "
            "api.utils.age_template.register_edge_labels()."
        )
    return label


def validate_max_hops(value: int, ceiling: int = 6) -> int:
    """Bound a path length so adversarial input cannot blow up the planner.

    Cypher does not parameterise path length quantifiers like `*1..N` —
    the integer must be interpolated. This helper rejects negative or
    over-large values and enforces a per-call ceiling.
    """
    n = int(value)
    if n < 1:
        raise ValueError(f"max_hops must be >= 1, got {n}")
    if n > ceiling:
        raise ValueError(f"max_hops must be <= {ceiling}, got {n}")
    return n


def render_path_quantifier(min_hops: int, max_hops: int, ceiling: int = 6) -> str:
    """Return a `*M..N` quantifier string after validation."""
    m = validate_max_hops(min_hops, ceiling=ceiling)
    n = validate_max_hops(max_hops, ceiling=ceiling)
    if m > n:
        raise ValueError(f"min_hops {m} > max_hops {n}")
    return f"*{m}..{n}"


def allowed_vertex_labels() -> frozenset[str]:
    """Read-only view of the current vertex allowlist (for tests/observability)."""
    return frozenset(_ALLOWED_VERTEX_LABELS)


def allowed_edge_labels() -> frozenset[str]:
    return frozenset(_ALLOWED_EDGE_LABELS)
