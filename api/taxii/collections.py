"""api.taxii.collections — TAXII 2.1 collection definitions.

Maps collection IDs to AGE graph query templates and STIX type filters.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CollectionDef:
    """Definition of a TAXII collection backed by graph queries."""

    id: str
    title: str
    description: str
    stix_types: list[str] = field(default_factory=list)
    graph_label_filter: list[str] = field(default_factory=list)


COLLECTIONS: dict[str, CollectionDef] = {
    "threat-intel": CollectionDef(
        id="threat-intel",
        title="Threat Intelligence",
        description="Layer 1 STIX objects: ThreatActor, Campaign, Malware, Tool, AttackPattern",
        stix_types=[
            "threat-actor",
            "campaign",
            "malware",
            "tool",
            "attack-pattern",
            "intrusion-set",
            "infrastructure",
            "relationship",
        ],
        graph_label_filter=[
            "ThreatActor",
            "Campaign",
            "Malware",
            "Tool",
            "AttackPattern",
            "IntrusionSet",
            "Infrastructure",
        ],
    ),
    "indicators": CollectionDef(
        id="indicators",
        title="Indicators",
        description="Indicator vertices: IP, domain, hash, URL indicators",
        stix_types=["indicator"],
        graph_label_filter=["Indicator", "CanonicalIP", "CanonicalDomain"],
    ),
    "vulnerabilities": CollectionDef(
        id="vulnerabilities",
        title="Vulnerabilities",
        description="Vulnerability vertices mapped to CVE identifiers",
        stix_types=["vulnerability"],
        graph_label_filter=["Vulnerability"],
    ),
}

# NOTE: Queries are constructed inline in server.py with parameterized
# filters and validate_label() for safe label interpolation.
